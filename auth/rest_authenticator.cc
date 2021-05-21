/*
 * Copyright (C) 2021 Criteo
 */

/*
 * This file is part of Scylla.
 *
 * Scylla is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Scylla is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Scylla.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "auth/rest_authenticator.hh"

#include <algorithm>
#include <chrono>
#include <random>
#include <string_view>
#include <optional>

#include <boost/algorithm/cxx11/all_of.hpp>
#include <seastar/core/seastar.hh>

#include "auth/authenticated_user.hh"
#include "auth/common.hh"
#include "auth/passwords.hh"
#include "auth/roles-metadata.hh"
#include "cql3/untyped_result_set.hh"
#include "log.hh"
#include "service/migration_manager.hh"
#include "utils/class_registrator.hh"
#include "database.hh"


namespace auth {
    namespace meta {
        namespace roles_valid_table {
            std::string_view creation_query() {
                static const sstring instance = sprint(
                        "CREATE TABLE %s ("
                        "  %s text PRIMARY KEY"
                        ")",
                        qualified_name,
                        role_col_name);
                return instance;
            }

            constexpr std::string_view
            qualified_name("system_auth.roles_valid");
        }
    }

    constexpr std::string_view
    rest_authenticator_name("com.criteo.scylladb.auth.RestAuthenticator");

// name of the hash column.
    static constexpr std::string_view
    SALTED_HASH = "salted_hash";
    static constexpr std::string_view
    DEFAULT_USER_NAME = meta::DEFAULT_SUPERUSER_NAME;
    static const sstring DEFAULT_USER_PASSWORD = sstring(meta::DEFAULT_SUPERUSER_NAME);

    static logging::logger plogger("rest_authenticator");

// To ensure correct initialization order, we unfortunately need to use a string literal.
    static const class_registrator<
            authenticator,
            rest_authenticator,
            cql3::query_processor &,
            ::service::migration_manager &> rest_auth_reg("com.criteo.scylladb.auth.RestAuthenticator");

    static thread_local auto rng_for_salt = std::default_random_engine(std::random_device{}());

    rest_authenticator::rest_authenticator(cql3::query_processor &qp, ::service::migration_manager &mm)
            : _qp(qp), _migration_manager(mm), _stopped(make_ready_future<>()) {}

    static bool has_salted_hash(const cql3::untyped_result_set_row &row) {
        return !row.get_or<sstring>(SALTED_HASH, "").empty();
    }

    static const sstring &update_row_query() {
        static const sstring update_row_query = format("UPDATE {} SET {} = ? WHERE {} = ?",
                                                       meta::roles_table::qualified_name,
                                                       SALTED_HASH,
                                                       meta::roles_table::role_col_name);
        return update_row_query;
    }

    static const sstring &create_row_query_roles() {
        static const sstring create_row_query_roles = format(
                "INSERT INTO {} ({}, can_login, is_superuser, {}) VALUES (?, true, false, ?)",
                meta::roles_table::qualified_name,
                meta::roles_table::role_col_name,
                SALTED_HASH);

        return create_row_query_roles;
    }

    static const sstring &create_row_query_roles_valid(uint32_t ttl) {
        static const sstring create_row_query_roles_valid = format(
                "INSERT INTO {} ({}) VALUES (?) USING TTL {}",
                meta::roles_valid_table::qualified_name,
                meta::roles_valid_table::role_col_name,
                ttl);

        return create_row_query_roles_valid;
    }

    static const sstring legacy_table_name{"credentials"};

    future<> rest_authenticator::create_default_if_missing() const {
        return default_role_row_satisfies(_qp, &has_salted_hash).then([this](bool exists) {
            if (!exists) {
                return _qp.execute_internal(
                        update_row_query(),
                        db::consistency_level::QUORUM,
                        internal_distributed_timeout_config(),
                        {passwords::hash(DEFAULT_USER_PASSWORD, rng_for_salt), DEFAULT_USER_NAME}).then([](auto &&) {
                    plogger.info("Created default superuser authentication record.");
                });
            }

            return make_ready_future<>();
        });
    }

    future<> rest_authenticator::start() {
        // Ensure the _authenticator_config has been well initialized
        if (_authenticator_config.rest_authenticator_endpoint_host == "") {
            throw std::invalid_argument("Missing configuration for rest_authenticator_endpoint_host. "
                                        "Did you call set_authenticator_config before calling start?");
        }
        // Init rest http client
        _rest_http_client = rest_http_client(_authenticator_config.rest_authenticator_endpoint_host,
                                             _authenticator_config.rest_authenticator_endpoint_port,
                                             _authenticator_config.rest_authenticator_endpoint_cafile_path);

        return once_among_shards([this] {
            auto f = create_metadata_table_if_missing(meta::roles_table::name,
                                                      _qp,
                                                      meta::roles_table::creation_query(),
                                                      _migration_manager)
                    .then([this]() {
                              return create_metadata_table_if_missing(meta::roles_valid_table::name,
                                                                      _qp,
                                                                      meta::roles_valid_table::creation_query(),
                                                                      _migration_manager);
                          }
                    );

            _stopped = do_after_system_ready(_as, [this] {
                return async([this] {
                    wait_for_schema_agreement(_migration_manager, _qp.db(), _as).get0();

                    if (any_nondefault_role_row_satisfies(_qp, &has_salted_hash).get0()) {
                        return;
                    }

                    create_default_if_missing().get0();
                });
            });

            return f;
        }).then([this]() {
            return _rest_http_client.init();
        });
    }

    future<> rest_authenticator::stop() {
        _as.request_abort();
        return _stopped.handle_exception_type([](const sleep_aborted &) {}).handle_exception_type(
                [](const abort_requested_exception &) {});
    }

    db::consistency_level rest_authenticator::consistency_for_user(std::string_view role_name) {
        if (role_name == DEFAULT_USER_NAME) {
            return db::consistency_level::QUORUM;
        }
        return db::consistency_level::LOCAL_ONE;
    }

    std::string_view rest_authenticator::qualified_java_name() const {
        return rest_authenticator_name;
    }

    bool rest_authenticator::require_authentication() const {
        return true;
    }

    authentication_option_set rest_authenticator::supported_options() const {
        return authentication_option_set{authentication_option::password};
    }

    authentication_option_set rest_authenticator::alterable_options() const {
        return authentication_option_set{authentication_option::password};
    }

    future <authenticated_user> rest_authenticator::authenticate(
            const credentials_map &credentials) const {
        if (!credentials.contains(USERNAME_KEY)) {
            plogger.info("Required key 'USERNAME' is missing");
            throw exceptions::authentication_exception(format("Required key '{}' is missing", USERNAME_KEY));
        }
        if (!credentials.contains(PASSWORD_KEY)) {
            plogger.info("Required key 'PASSWORD' is missing");
            throw exceptions::authentication_exception(format("Required key '{}' is missing", PASSWORD_KEY));
        }

        auto &username = credentials.at(USERNAME_KEY);
        auto &password = credentials.at(PASSWORD_KEY);

        // Here was a thread local, explicit cache of prepared statement. In normal execution this is
        // fine, but since we in testing set up and tear down system over and over, we'd start using
        // obsolete prepared statements pretty quickly.
        // Rely on query processing caching statements instead, and lets assume
        // that a map lookup string->statement is not gonna kill us much.
        return futurize_invoke([this, username, password] {
            static const sstring query_roles = format("SELECT {} FROM {} WHERE {} = ?",
                                                      SALTED_HASH,
                                                      meta::roles_table::qualified_name,
                                                      meta::roles_table::role_col_name);
            static const sstring query_roles_valid = format("SELECT {}  FROM {} WHERE {} = ?",
                                                            meta::roles_valid_table::role_col_name,
                                                            meta::roles_valid_table::qualified_name,
                                                            meta::roles_valid_table::role_col_name);

            return when_all(
                    _qp.execute_internal(
                            query_roles,
                            consistency_for_user(username),
                            internal_distributed_timeout_config(),
                            {username},
                            true),
                    _qp.execute_internal(
                            query_roles_valid,
                            consistency_for_user(username),
                            internal_distributed_timeout_config(),
                            {username},
                            true)
            );
        }).then_wrapped([=](future <std::tuple<future < ::shared_ptr < cql3::untyped_result_set>>,
                            future<::shared_ptr < cql3::untyped_result_set>> >> f)
        {
            try {
                auto tup = f.get0();
                auto res_roles = std::get<0>(tup).get0();
                auto res_roles_valid = std::get<1>(tup).get0();

                auto salted_hash = std::optional<sstring>();
                if (!res_roles->empty()) {
                    salted_hash = res_roles->one().get_opt<sstring>(SALTED_HASH);
                }
                auto role_name = std::optional<sstring>();
                if (!res_roles_valid->empty()) {
                    role_name = res_roles_valid->one().get_opt<sstring>(meta::roles_valid_table::role_col_name);
                }

                // If not super user (super user is local only) and the username is not in roles_valid or salted_hash empty or bad password
                // call external endpoint
                if (username == DEFAULT_USER_NAME && (!salted_hash || !passwords::check(password, *salted_hash))) {
                    std::throw_with_nested(exceptions::authentication_exception("Bad password for superuser"));
                } else if (username != DEFAULT_USER_NAME &&
                           (!role_name || !salted_hash || !passwords::check(password, *salted_hash))) {
                    bool create_user = res_roles->empty();

                    // TODO manage retry?
                    // TODO add prometheus metrics on auth failure/success...?
                    // TODO better delete only if date passed and repopulate async instead of ttl that just remove the entry from the table
                    plogger.info("Authenticating username {} from rest endpoint", username);
                    // This timeout only timebox return to client the task and callback are not cancelled
                    return with_timeout(
                            timer<>::clock::now() +
                            std::chrono::seconds(_authenticator_config.rest_authenticator_endpoint_timeout),
                            _rest_http_client.connect())
                            .then([username, password](
                                    std::unique_ptr <rest_http_client::connection> c) {
                                return seastar::do_with(
                                        std::move(c),
                                        [username, password](auto &c) {
                                            return c->do_get_groups(username, password);
                                        });
                            })
                            .then([this, create_user, username, password](role_set roles) {
                                return create_or_update(create_user, username, password, roles);
                            });
                }

                return make_ready_future<authenticated_user>(username);
            } catch (std::system_error &) {
                std::throw_with_nested(exceptions::authentication_exception("Could not verify password"));
            } catch (exceptions::request_execution_exception &e) {
                std::throw_with_nested(exceptions::authentication_exception(e.what()));
            } catch (exceptions::authentication_exception &e) {
                std::throw_with_nested(e);
            } catch (...) {
                std::throw_with_nested(exceptions::authentication_exception("authentication failed"));
            }
        });
    }

    future <authenticated_user>
    rest_authenticator::create_or_update(bool create_user, sstring username, sstring password, role_set &roles) const {
        return do_with(std::move(roles), [this, create_user, username, password](role_set &roles) {
            authentication_options authen_options;
            authen_options.password = std::optional < std::string > {password};

            if (create_user) {
                plogger.info("Create role for username {}", username);
                return rest_authenticator::create_with_groups(username, roles, authen_options).then([username] {
                    return make_ready_future<authenticated_user>(username);
                });
            }
            plogger.info("Update password for username {}", username);
            return rest_authenticator::alter_with_groups(username, roles, authen_options).then([username] {
                return make_ready_future<authenticated_user>(username);
            });
        });
    }

    future<> rest_authenticator::create(std::string_view role_name, const authentication_options &options) const {
        role_set roles;
        return create_with_groups(sstring(role_name), roles, options);
    }

    future<> rest_authenticator::create_with_groups(sstring role_name, role_set &roles,
                                                    const authentication_options &options) const {
        if (!options.password) {
            return make_ready_future<>();
        }

        return when_all(
                _qp.execute_internal(
                        create_row_query_roles(),
                        consistency_for_user(role_name),
                        internal_distributed_timeout_config(),
                        {role_name, passwords::hash(*options.password, rng_for_salt)}),
                _qp.execute_internal(
                        create_row_query_roles_valid(_authenticator_config.rest_authenticator_endpoint_ttl),
                        consistency_for_user(role_name),
                        internal_distributed_timeout_config(),
                        {role_name})
        ).then([this, role_name, &roles](auto f) {
            return modify_membership(role_name, roles);
        }).discard_result();
    }

    future<> rest_authenticator::alter(std::string_view role_name, const authentication_options &options) const {
        role_set roles;
        return alter_with_groups(sstring(role_name), roles, options);
    }

    future<> rest_authenticator::alter_with_groups(sstring role_name, role_set &roles,
                                                   const authentication_options &options) const {
        if (!options.password) {
            return make_ready_future<>();
        }

        static const sstring query = format("UPDATE {} SET {} = ? WHERE {} = ?",
                                            meta::roles_table::qualified_name,
                                            SALTED_HASH,
                                            meta::roles_table::role_col_name);

        return when_all(
                _qp.execute_internal(
                        query,
                        consistency_for_user(role_name),
                        internal_distributed_timeout_config(),
                        {passwords::hash(*options.password, rng_for_salt), role_name}),
                _qp.execute_internal(
                        create_row_query_roles_valid(_authenticator_config.rest_authenticator_endpoint_ttl),
                        consistency_for_user(role_name),
                        internal_distributed_timeout_config(),
                        {role_name})
        ).then([this, role_name, &roles](auto f) {
            return modify_membership(role_name, roles);
        }).discard_result();
    }

    future<> rest_authenticator::drop(std::string_view name) const {
        static const sstring query = format("DELETE {} FROM {} WHERE {} = ?",
                                            SALTED_HASH,
                                            meta::roles_table::qualified_name,
                                            meta::roles_table::role_col_name);

        return _qp.execute_internal(
                query, consistency_for_user(name),
                internal_distributed_timeout_config(),
                {sstring(name)}).discard_result();
    }


    future<>
    rest_authenticator::modify_membership(sstring grantee_name, role_set &roles) const {
        const auto modify_roles = [this, grantee_name, &roles] {
            const auto query = format(
                    "UPDATE {} SET member_of = ? WHERE {} = ?",
                    meta::roles_table::qualified_name,
                    meta::roles_table::role_col_name);

            return _qp.execute_internal(
                    query,
                    consistency_for_user(grantee_name),
                    internal_distributed_timeout_config(),
                    {roles, grantee_name});
        };

        return modify_roles().discard_result();
    }

    future <custom_options> rest_authenticator::query_custom_options(std::string_view role_name) const {
        return make_ready_future<custom_options>();
    }

    const resource_set &rest_authenticator::protected_resources() const {
        static const resource_set resources({make_data_resource(meta::AUTH_KS, meta::roles_table::name)});
        return resources;
    }

    ::shared_ptr <sasl_challenge> rest_authenticator::new_sasl_challenge() const {
        return ::make_shared<plain_sasl_challenge>([this](std::string_view username, std::string_view password) {
            credentials_map credentials{};
            credentials[USERNAME_KEY] = sstring(username);
            credentials[PASSWORD_KEY] = sstring(password);
            return this->authenticate(credentials);
        });
    }

}

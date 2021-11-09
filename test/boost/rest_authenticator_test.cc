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

#include <seastar/testing/test_case.hh>
#include <seastar/http/httpd.hh>
#include "test/lib/cql_test_env.hh"
#include "alternator/base64.hh"
#include "cql3/query_processor.hh"
#include "cql3/untyped_result_set.hh"
#include "auth/common.hh"
#include "auth/passwords.hh"
#include "auth/rest_authenticator.hh"
#include "auth/rest_role_manager.hh"
#include "auth/roles-metadata.hh"


cql_test_config rest_authenticator_on() {
    cql_test_config cfg;
    cfg.db_config->authenticator("com.criteo.scylladb.auth.RestAuthenticator");
    cfg.db_config->rest_authenticator_endpoint_host("localhost");
    cfg.db_config->rest_authenticator_endpoint_port(54321);
    cfg.db_config->rest_authenticator_endpoint_cafile_path("tools/rest_authenticator_server/ssl/ca.crt");
    cfg.db_config->rest_authenticator_endpoint_ttl(10);
    cfg.db_config->rest_authenticator_endpoint_timeout(10);

    cfg.db_config->role_manager("com.criteo.scylladb.auth.RestManager");
    cfg.db_config->authorizer("CassandraAuthorizer");
    return cfg;
}

class rest_authentication_handler : public seastar::httpd::handler_base {
    virtual future <std::unique_ptr<seastar::httpd::reply>>
    handle(const sstring &path, std::unique_ptr <seastar::httpd::request> req,
           std::unique_ptr <seastar::httpd::reply> rep) override {
        using namespace seastar::httpd;

        auto auth_header = req->get_header("Authorization");
        if (auth_header.substr(0, 6) != "Basic ") {
            rep->set_status(seastar::httpd::reply::status_type::bad_request);
            rep->done();
            return make_ready_future < std::unique_ptr < reply >> (std::move(rep));
        }

        auto auth_token = auth_header.substr(6);
        auto auth_token_str = base64_decode(auth_token);

        if (auth_token_str.find("alice") != sstring::npos) {
            rep->write_body(sstring("json"), sstring("{\"groups\": [\"scylla-rw\", \"other\"]}"));
        } else if (auth_token_str.find("john.doe") != sstring::npos) {
            rep->set_status(seastar::httpd::reply::status_type::not_found);
            rep->done();
        } else {
            rep->set_status(seastar::httpd::reply::status_type::unauthorized);
            rep->done();
        }

        return make_ready_future < std::unique_ptr < reply >> (std::move(rep));
    }
};

future<> with_dummy_authentication_server(std::function<void(cql_test_env & )> func) {
    return seastar::async([func] {
        auto conf = std::move(rest_authenticator_on());

        seastar::global_logger_registry().set_logger_level("httpd", seastar::log_level::debug);

        httpd::http_server_control httpd;
        httpd.start("dummy_authentication_server").get();
        auto stop_httpd = defer([&httpd] { httpd.stop().get(); });

        // setup TLS for https
        tls::credentials_builder b;
        b.set_dh_level(tls::dh_params::level::MEDIUM);
        // TODO find a better way to resolve path of certificates
        b.set_x509_key_file("tools/rest_authenticator_server/ssl/rest_api.crt",
                            "tools/rest_authenticator_server/ssl/rest_api.key",
                            seastar::tls::x509_crt_format::PEM).get();
        b.set_priority_string(db::config::default_tls_priority);

        httpd.server().invoke_on_all([b](http_server &server) {
            auto creds = b.build_server_credentials();
            server.set_tls_credentials(creds);
        }).get();

        // setup http routes
        httpd.set_routes([](routes &r) {
            r.put(seastar::httpd::operation_type::GET, "/api/v1/auth/user/groups", new rest_authentication_handler());
        }).get();
        httpd.listen(ipv4_addr("127.0.0.1", 54321)).get();

        // start cql test environment and execute test function
        do_with_cql_env_thread([func = std::move(func)](cql_test_env &env) {
            return func(env);
        }, conf).get();
    });
}

struct record final {
    sstring name;
    bool is_superuser;
    bool can_login;
    auth::role_set member_of;
    sstring salted_hash;
};

static future <std::optional<record>> find_record(cql3::query_processor &qp, std::string_view role_name) {
    static const sstring query = format("SELECT * FROM {} WHERE {} = ?",
                                        auth::meta::roles_table::qualified_name,
                                        auth::meta::roles_table::role_col_name);
    return qp.execute_internal(
            query,
            db::consistency_level::LOCAL_ONE,
            auth::internal_distributed_query_state(),
            {sstring(role_name)},
            true).then([](::shared_ptr <cql3::untyped_result_set> results) {
        if (results->empty()) {
            return std::optional<record>();
        }

        const cql3::untyped_result_set_row &row = results->one();

        return std::make_optional(
                record{
                        row.get_as<sstring>(sstring(auth::meta::roles_table::role_col_name)),
                        row.get_or<bool>("is_superuser", false),
                        row.get_or<bool>("can_login", false),
                        (row.has("member_of")
                         ? row.get_set<sstring>("member_of")
                         : auth::role_set()),
                        row.get_as<sstring>("salted_hash")});
    });
}

static future<bool> can_login(cql3::query_processor &qp, std::string_view role_name) {
    return find_record(qp, role_name).then([](std::optional <record> mr) {
        if (mr) {
            record r = *mr;
            return r.can_login;
        }
        return false;
    });
}

static future<bool> is_superuser(cql3::query_processor &qp, std::string_view role_name) {
    return find_record(qp, role_name).then([](std::optional <record> mr) {
        if (mr) {
            record r = *mr;
            return r.is_superuser;
        }
        return false;
    });
}

static future <auth::role_set> get_role_set(cql3::query_processor &qp, std::string_view role_name) {
    return find_record(qp, role_name).then([](std::optional <record> mr) {
        if (mr) {
            record r = *mr;
            return r.member_of;
        }
        return auth::role_set();
    });
}

static future <sstring> get_salted_hash(cql3::query_processor &qp, std::string_view role_name) {
    return find_record(qp, role_name).then([](std::optional <record> mr) {
        if (mr) {
            record r = *mr;
            return r.salted_hash;
        }
        return sstring();
    });
}

static future<> delete_record_valid(cql3::query_processor &qp, std::string_view role_name) {
    static const sstring query = format("DELETE FROM {} WHERE {} = ?",
                                        auth::meta::roles_valid_table::qualified_name,
                                        auth::meta::roles_valid_table::role_col_name);
    return qp.execute_internal(
            query,
            db::consistency_level::LOCAL_ONE,
            auth::internal_distributed_query_state(),
            {sstring(role_name)},
            true).discard_result();
};

static future <std::optional<sstring>> find_record_valid(cql3::query_processor &qp, std::string_view role_name) {
    static const sstring query = format("SELECT * FROM {} WHERE {} = ?",
                                        auth::meta::roles_valid_table::qualified_name,
                                        auth::meta::roles_valid_table::role_col_name);
    return qp.execute_internal(
            query,
            db::consistency_level::LOCAL_ONE,
            auth::internal_distributed_query_state(),
            {sstring(role_name)},
            true).then([](::shared_ptr <cql3::untyped_result_set> results) {
        if (results->empty()) {
            return std::optional<sstring>();
        }

        const cql3::untyped_result_set_row &row = results->one();
        return std::make_optional(row.get_as<sstring>(sstring(auth::meta::roles_valid_table::role_col_name)));
    });
};

static future <sstring> require_record_valid(cql3::query_processor &qp, std::string_view role_name) {
    return find_record_valid(qp, role_name).then([role_name](std::optional <sstring> mr) {
        if (!mr) {
            throw auth::nonexistant_role(role_name);
        }
        return make_ready_future<sstring>(*mr);
    });
}

static thread_local auto rng_for_salt = std::default_random_engine(std::random_device{}());

static future<> create_superuser_role(cql3::query_processor &qp) {
    static const sstring query = format(
            "INSERT INTO {} ({}, is_superuser, can_login, salted_hash) VALUES (?, true, true, ?)",
            auth::meta::roles_table::qualified_name,
            auth::meta::roles_table::role_col_name);
    return qp.execute_internal(
            query,
            db::consistency_level::QUORUM,
            auth::internal_distributed_query_state(),
            {auth::meta::DEFAULT_SUPERUSER_NAME,
             auth::passwords::hash(sstring(auth::meta::DEFAULT_SUPERUSER_NAME), rng_for_salt)}).discard_result();
}

SEASTAR_TEST_CASE(rest_authenticator_conf) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();
            BOOST_REQUIRE_EQUAL(a.qualified_java_name(), "com.criteo.scylladb.auth.RestAuthenticator");
            BOOST_REQUIRE(a.require_authentication());

            auto &authenticator_config = a.get_authenticator_config();
            BOOST_REQUIRE_EQUAL(authenticator_config.rest_authenticator_endpoint_host, "localhost");
            BOOST_REQUIRE_EQUAL(authenticator_config.rest_authenticator_endpoint_port, 54321);
            BOOST_REQUIRE_EQUAL(authenticator_config.rest_authenticator_endpoint_cafile_path,
                                "tools/rest_authenticator_server/ssl/ca.crt");
            BOOST_REQUIRE_EQUAL(authenticator_config.rest_authenticator_endpoint_ttl, 10);
            BOOST_REQUIRE_EQUAL(authenticator_config.rest_authenticator_endpoint_timeout, 10);

            auto &authorizer = env.local_auth_service().underlying_authorizer();
            BOOST_REQUIRE_EQUAL(authorizer.qualified_java_name(),
                                "org.apache.cassandra.auth.CassandraAuthorizer");

            auto &rm = env.local_auth_service().underlying_role_manager();
            BOOST_REQUIRE_EQUAL(rm.qualified_java_name(), "com.criteo.scylladb.auth.RestManager");
        });
}

SEASTAR_TEST_CASE(valid_user) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            auto auth_user = a.authenticate(creds).get();
            BOOST_REQUIRE_EQUAL(auth_user.name.value(), "alice");

            // Check state in DB
            auto &qp = env.local_qp();
            BOOST_REQUIRE(can_login(qp, "alice").get());
            BOOST_REQUIRE(can_login(qp, "norole").get() == false);

            // Check state through role_manager should be align with DB state
            auto &rm = env.local_auth_service().underlying_role_manager();
            BOOST_REQUIRE(rm.can_login("alice").get());
            BOOST_REQUIRE_EXCEPTION(rm.can_login("norole").get(), exceptions::invalid_request_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Role norole doesn't exist."));
        });
}

SEASTAR_TEST_CASE(valid_superuser) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &qp = env.local_qp();
            create_superuser_role(qp).get();

            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("cassandra")},
                    {auth::authenticator::PASSWORD_KEY, sstring("cassandra")}
            };

            auto auth_user = a.authenticate(creds).get();
            BOOST_REQUIRE_EQUAL(auth_user.name.value(), "cassandra");
            BOOST_REQUIRE(is_superuser(qp, "cassandra").get());
        });
}

SEASTAR_TEST_CASE(bad_password_superuser) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("cassandra")},
                    {auth::authenticator::PASSWORD_KEY, sstring("bad_password")}
            };

            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Bad password for superuser"));
        });
}

SEASTAR_TEST_CASE(unknown_user) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("john.doe")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Unknown username"));

            // Check state in DB
            auto &qp = env.local_qp();
            BOOST_REQUIRE(can_login(qp, "john.doe").get() == false);

            // Check state through role_manager should be align with DB state
            auto &rm = env.local_auth_service().underlying_role_manager();
            BOOST_REQUIRE_EXCEPTION(rm.can_login("john.doe").get(), exceptions::invalid_request_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Role john.doe doesn't exist."));
        });
}

SEASTAR_TEST_CASE(invalid_credentials) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("foo.bar")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains("Bad password"));

            // Check state in DB
            auto &qp = env.local_qp();
            BOOST_REQUIRE(can_login(qp, "foo.bar").get() == false);

            // Check state through role_manager should be align with DB state
            auto &rm = env.local_auth_service().underlying_role_manager();
            BOOST_REQUIRE_EXCEPTION(rm.can_login("foo.bar").get(), exceptions::invalid_request_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Role foo.bar doesn't exist."));
        });
}


SEASTAR_TEST_CASE(user_has_roles) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            a.authenticate(creds).discard_result().get();

            auth::role_set roles;
            roles.insert(sstring("scylla-rw"));
            roles.insert(sstring("other"));

            // Check state in DB
            auto &qp = env.local_qp();
            BOOST_REQUIRE_EQUAL(get_role_set(qp, "alice").get(), roles);

            // Check state through role_manager
            roles.insert(sstring("alice")); // query_granted also return current role name in the role set
            auto &rm = env.local_auth_service().underlying_role_manager();
            BOOST_REQUIRE_EQUAL(rm.query_granted("alice", auth::recursive_role_query::no).get(), roles);
        });
}

SEASTAR_TEST_CASE(user_expired_is_well_recreated) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            a.authenticate(creds).discard_result().get();

            auto &qp = env.local_qp();
            BOOST_REQUIRE_EQUAL(require_record_valid(qp, "alice").get(), "alice");

            // To ensure deletion of expired rows (TTL)
            forward_jump_clocks(20s);
            BOOST_REQUIRE_EXCEPTION(require_record_valid(qp, "alice").get(), exceptions::invalid_request_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Role alice doesn't exist."));

            a.authenticate(creds).get();
            // Entry has been well recreated in the DB
            BOOST_REQUIRE_EQUAL(require_record_valid(qp, "alice").get(), "alice");
        });
}


SEASTAR_TEST_CASE(user_password_is_updated) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            a.authenticate(creds).discard_result().get();

            auto &qp = env.local_qp();
            BOOST_REQUIRE_EQUAL(require_record_valid(qp, "alice").get(), "alice");
            sstring salted_hash = get_salted_hash(qp, "alice").get();

            auto creds2 = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password2")}
            };

            a.authenticate(creds2).discard_result().get();
            BOOST_REQUIRE_EQUAL(require_record_valid(qp, "alice").get(), "alice");

            sstring salted_hash2 = get_salted_hash(qp, "alice").get();
            BOOST_REQUIRE(salted_hash != salted_hash2);
        });
}


SEASTAR_TEST_CASE(update_superuser_password) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &qp = env.local_qp();
            create_superuser_role(qp).get();

            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("cassandra")},
                    {auth::authenticator::PASSWORD_KEY, sstring("cassandra")}
            };

            auto auth_user = a.authenticate(creds).get();
            BOOST_REQUIRE_EQUAL(auth_user.name.value(), "cassandra");
            BOOST_REQUIRE(is_superuser(qp, "cassandra").get());

            // Alter superuser password
            auth::authentication_options authen_options;
            authen_options.password = std::optional < std::string > {"123456"};
            a.alter("cassandra", authen_options).get();

            // Ensure old password doesn't work
            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains(
                                            "Bad password for superuser"));

            // Ensure new password works and user rights haven't been affected
            auto creds_new = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("cassandra")},
                    {auth::authenticator::PASSWORD_KEY, sstring("123456")}
            };

            auto auth_user_new = a.authenticate(creds_new).get();
            BOOST_REQUIRE_EQUAL(auth_user_new.name.value(), "cassandra");
            BOOST_REQUIRE(is_superuser(qp, "cassandra").get());
        });
}


SEASTAR_TEST_CASE(get_list_of_roles) {
        return with_dummy_authentication_server([](cql_test_env &env) {
            auto &a = env.local_auth_service().underlying_authenticator();
            auto &rm = env.local_auth_service().underlying_role_manager();

            auth::role_set roles;
            roles.insert(sstring("tester"));

            BOOST_REQUIRE_EQUAL(rm.query_all().get(), roles);

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            a.authenticate(creds).get();

            roles.insert(sstring("scylla-rw"));
            roles.insert(sstring("other"));
            roles.insert(sstring("alice"));

            BOOST_REQUIRE_EQUAL(rm.query_all().get(), roles);
        });
}

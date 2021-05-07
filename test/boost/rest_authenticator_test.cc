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

cql_test_config rest_authenticator_on() {
    cql_test_config cfg;
    cfg.db_config->authenticator("com.criteo.scylladb.auth.RestAuthenticator");
    cfg.db_config->rest_authenticator_endpoint_host("localhost");
    cfg.db_config->rest_authenticator_endpoint_port(54321);
    cfg.db_config->rest_authenticator_endpoint_cafile_path("tools/rest_authenticator_server/ssl/ca.crt");
    cfg.db_config->rest_authenticator_endpoint_ttl(10); // TODO confirm unit
    cfg.db_config->rest_authenticator_endpoint_timeout(10);// TODO confirm unit
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

        std::cout << "***** received auth_token = " << auth_token << std::endl;
        std::cout << "***** received auth_token_str = " << auth_token_str << std::endl;

        if (auth_token_str.find("alice") != sstring::npos) {
            rep->write_body(sstring("json"), sstring("{\"groups\": [\"scylla-rw\"]}"));
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


SEASTAR_TEST_CASE(rest_authenticator_conf) {
        return with_dummy_authentication_server([] (cql_test_env& env) {
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

        });
}


SEASTAR_TEST_CASE(valid_user) {
        return with_dummy_authentication_server([] (cql_test_env& env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("alice")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            auto auth_user = a.authenticate(creds).get();
            BOOST_REQUIRE_EQUAL(auth_user.name.value(), "alice");
        });
}

SEASTAR_TEST_CASE(unknown_user) {
        return with_dummy_authentication_server([] (cql_test_env& env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("john.doe")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains("Unknown username"));
        });
}

SEASTAR_TEST_CASE(invalid_credentials) {
        return with_dummy_authentication_server([] (cql_test_env& env) {
            auto &a = env.local_auth_service().underlying_authenticator();

            auto creds = auth::authenticator::credentials_map{
                    {auth::authenticator::USERNAME_KEY, sstring("foo.bar")},
                    {auth::authenticator::PASSWORD_KEY, sstring("password")}
            };

            BOOST_REQUIRE_EXCEPTION(a.authenticate(creds).get(), exceptions::authentication_exception,
                                    seastar::testing::exception_predicate::message_contains("Bad password"));
        });
}
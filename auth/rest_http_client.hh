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

#include <seastar/net/api.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/tls.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/future-util.hh>
#include "picojson/picojson.h"
#include "auth/rest_response_parser.hh"
#include "alternator/base64.hh"


namespace auth {

    class rest_http_client {
        std::string _server;
        int _port;
        std::string _ca_file;
        shared_ptr <tls::certificate_credentials> _creds;
        sstring _request;

    public:
        rest_http_client() {};

        rest_http_client(std::string server, int port, std::string ca_file)
                : _server(server), _port(port), _ca_file(ca_file),
                  _creds(make_shared<tls::certificate_credentials>()) {}

        class connection {
        private:
            connected_socket _fd;
            input_stream<char> _read_buf;
            output_stream<char> _write_buf;
            rest_response_parser _parser;
            sstring _request;

            future <std::vector<std::string>> extract_groups(temporary_buffer<char> buf, uint content_len) {
                const char *json = buf.get();
                picojson::value v;
                std::string err;
                picojson::parse(v, json, json + content_len, &err);
                if (!err.empty()) {
                    std::throw_with_nested(exceptions::authentication_exception(
                            format("Bad response: not able to parse body: {}", err)));
                }

                // check if the type of the value is "object"
                if (!v.is<picojson::object>()) {
                    std::throw_with_nested(exceptions::authentication_exception(
                            "Bad response: response is not a dict"));
                }

                const picojson::value::object &obj = v.get<picojson::object>();
                auto it = obj.find("groups");
                if (it == obj.end()) {
                    std::throw_with_nested(exceptions::authentication_exception(
                            "Bad response: doesn't contain groups field"));
                }

                auto pv_groups = it->second;
                if (!pv_groups.is<picojson::array>()) {
                    std::throw_with_nested(exceptions::authentication_exception(
                            "Bad response: groups field doesn't contain an array"));
                }

                const picojson::value::array &p_groups = pv_groups.get<picojson::array>();
                std::vector <std::string> groups;

                // TODO filter groups to add (For ex. only add groups containing scylla... to avoid storing all groups)
                for (auto p_group : p_groups) {
                    if (p_group.is<std::string>()) {
                        auto group = p_group.get<std::string>();
                        groups.push_back(group);
                    }
                }

                return make_ready_future < std::vector < std::string >> (groups);
            }

            future <std::vector<std::string>>
            get_groups_from_body(std::unique_ptr <auth::http_response, std::default_delete<auth::http_response>> rsp) {
                auto it = rsp->_headers.find("content-length");
                if (it == rsp->_headers.end()) {
                    std::throw_with_nested(
                            exceptions::authentication_exception("Bad response: missing Content-Length header"));
                }
                auto content_len = std::stoi(it->second);

                // Read HTTP response body
                return _read_buf.read_exactly(content_len)
                        .then([this, content_len](temporary_buffer<char> buf) {
                            return extract_groups(std::move(buf), content_len);
                        });
            }

            std::string get_authorization_header(sstring username, sstring password) {
                sstring authorization = format("{}:{}", username, password);
                auto bytes_authorization = bytes_view(reinterpret_cast<const signed char *>(authorization.c_str()),
                                                      authorization.size());
                return base64_encode(bytes_authorization);
            }

        public:
            connection(connected_socket &&fd, sstring request)
                    : _fd(std::move(fd)), _read_buf(_fd.input()), _write_buf(_fd.output()), _request(request) {}

            ~connection() {}

            future <std::vector<std::string>> do_get_groups(sstring username, sstring password) {
                std::string b64_authorization = get_authorization_header(username, password);
                sstring request = format(_request.c_str(), b64_authorization);

                return _write_buf.write(request)
                        .then([this] {
                            return _write_buf.flush();
                        })
                        .then([this] {
                            _parser.init();
                            return _read_buf.consume(_parser);
                        })
                        .then([this] {
                            if (_parser.eof()) {
                                std::throw_with_nested(
                                        exceptions::authentication_exception("Bad response: empty response"));
                            }
                            auto _rsp = _parser.get_parsed_response();

                            switch (_rsp->_status) {
                                case 200 :
                                    return get_groups_from_body(std::move(_rsp));
                                    break;
                                case 401 :
                                    std::throw_with_nested(exceptions::authentication_exception("Bad password"));
                                    break;
                                case 404 :
                                    std::throw_with_nested(
                                            exceptions::authentication_exception("Unknown username"));
                                    break;
                                default :
                                    break;
                            }
                            std::throw_with_nested(exceptions::authentication_exception(
                                    format("Issue to authenticate with http status code {}", _rsp->_status)));
                        });

            }
        };

        future<> init() {
            _request = format("GET /api/v1/auth/user/groups HTTP/1.1\r\n"
                              "Host: {}:{}\r\n"
                              "Authorization: Basic {{}}\r\n"
                              "Accept: application/json\r\n\r\n",
                              _server, _port);

            // Load system CA trust
            // TODO see tls.credentials_builder in Seastar
            auto f = _creds->set_system_trust();
            if (_ca_file != "") {
                f = f.then([this] { return _creds->set_x509_trust_file(_ca_file, tls::x509_crt_format::PEM); });
            }
            return f.discard_result();
        }

        future <std::unique_ptr<connection>> connect() const {
            return net::dns::resolve_name(_server)
                    // TODO add some socket timeout
                    .then([this](seastar::net::inet_address ip) {
                        socket_address sa(ip, _port);
                        return tls::connect(_creds, sa, _server);
                    })
                    .then([this](connected_socket fd) {
                        return std::make_unique<connection>(std::move(fd), _request);
                    });
        }
    };
}
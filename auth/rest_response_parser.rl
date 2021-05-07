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

// Added to manage status and enforce all header fields to be in lowercase
#include <seastar/core/ragel.hh>
#include <memory>
#include <unordered_map>

namespace auth {

struct http_response {
    sstring _version;
    int _status;
    std::unordered_map<sstring, sstring> _headers;
};

%% machine http_response;

%%{

access _fsm_;

action mark {
    g.mark_start(p);
}

action store_version {
    _rsp->_version = str();
}

action store_status {
    _rsp->_status = std::stoi(str());
}

action store_field_name {
    _field_name = str();
}

action store_value {
    _value = str();
}

action assign_field {
    std::transform(_field_name.begin(), _field_name.end(), _field_name.begin(), ::tolower);
    _rsp->_headers[_field_name] = std::move(_value);
}

action extend_field  {
    _rsp->_headers[_field_name] += sstring(" ") + std::move(_value);
}

action done {
    done = true;
    fbreak;
}

cr = '\r';
lf = '\n';
crlf = '\r\n';
tchar = alpha | digit | '-' | '!' | '#' | '$' | '%' | '&' | '\'' | '*'
        | '+' | '.' | '^' | '_' | '`' | '|' | '~';

sp = ' ';
ht = '\t';

sp_ht = sp | ht;

http_version = 'HTTP/' (digit '.' digit) >mark %store_version;
http_status = (digit digit digit) >mark %store_status;

field = tchar+ >mark %store_field_name;
value = any* >mark %store_value;
start_line = http_version space http_status space (any - cr - lf)* crlf;
header_1st = (field sp_ht* ':' value :> crlf) %assign_field;
header_cont = (sp_ht+ value sp_ht* crlf) %extend_field;
header = header_1st header_cont*;
main := start_line header* :> (crlf @done);

}%%

class rest_response_parser : public ragel_parser_base<rest_response_parser> {
    %% write data nofinal noprefix;
public:
    enum class state {
        error,
        eof,
        done,
    };
    std::unique_ptr<http_response> _rsp;
    sstring _field_name;
    sstring _value;
    state _state;
public:
    void init() {
        init_base();
        _rsp.reset(new http_response());
        _state = state::eof;
        %% write init;
    }
    char* parse(char* p, char* pe, char* eof) {
        sstring_builder::guard g(_builder, p, pe);
        auto str = [this, &g, &p] { g.mark_end(p); return get_str(); };
        bool done = false;
        if (p != pe) {
            _state = state::error;
        }
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmisleading-indentation"
#endif
        %% write exec;
#ifdef __clang__
#pragma clang diagnostic pop
#endif
        if (!done) {
            p = nullptr;
        } else {
            _state = state::done;
        }
        return p;
    }
    auto get_parsed_response() {
        return std::move(_rsp);
    }
    bool eof() const {
        return _state == state::eof;
    }
};

}

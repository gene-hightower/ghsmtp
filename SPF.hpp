/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SPF_DOT_HPP
#define SPF_DOT_HPP

#include <ostream>
#include <unordered_map>

#include <arpa/inet.h> // in_addr

extern "C" {
#include <spf2/spf.h>
}

#include "Logging.hpp"

namespace SPF {

enum class Result {
  INVALID = SPF_RESULT_INVALID,
  NEUTRAL = SPF_RESULT_NEUTRAL,
  PASS = SPF_RESULT_PASS,
  FAIL = SPF_RESULT_FAIL,
  SOFTFAIL = SPF_RESULT_SOFTFAIL,
  NONE = SPF_RESULT_NONE,
  TEMPERROR = SPF_RESULT_TEMPERROR,
  PERMERROR = SPF_RESULT_PERMERROR,
};

extern std::unordered_map<Result, char const*> result_to_string;

class Server {
public:
  Server(Server const&) = delete;
  Server& operator=(Server const&) = delete;

  explicit Server(char const* fqdn)
  {
    srv_ = CHECK_NOTNULL(SPF_server_new(SPF_DNS_RESOLV, 1));
    if (fqdn) {
      CHECK_EQ(SPF_E_SUCCESS, SPF_server_set_rec_dom(srv_, fqdn));
    }
  }
  ~Server()
  {
    SPF_server_free(srv_);
  }

private:
  SPF_server_t* srv_;

  friend class Request;
};

class Request {
public:
  Request(Request const&) = delete;
  Request& operator=(Request const&) = delete;

  explicit Request(Server const& srv)
  {
    req_ = CHECK_NOTNULL(SPF_request_new(srv.srv_));
  }
  ~Request()
  {
    SPF_request_free(req_);
  }
  void set_ipv4_str(char const* ipv4)
  {
    CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_ipv4_str(req_, ipv4));
  }
  void set_helo_dom(char const* dom)
  {
    CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_helo_dom(req_, dom));
  }
  void set_env_from(char const* frm)
  {
    CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_env_from(req_, frm));
  }

private:
  SPF_request_t* req_;

  friend class Response;
};

class Response {
public:
  Response(Response const&) = delete;
  Response& operator=(Response const&) = delete;

  explicit Response(Request const& req)
  {
    // We ignore the return code from this call, as everything we need
    // to know is in the SPF_response_t struct.
    SPF_request_query_mailfrom(req.req_, &res_);
  }
  ~Response()
  {
    SPF_response_free(res_);
  }
  Result result() const
  {
    return static_cast<Result>(SPF_response_result(res_));
  }
  char const* smtp_comment() const
  {
    return SPF_response_get_smtp_comment(res_);
  }
  char const* header_comment() const
  {
    return SPF_response_get_header_comment(res_);
  }
  char const* received_spf() const
  {
    return SPF_response_get_received_spf(res_);
  }

private:
  SPF_response_t* res_;
};

} // namespace SPF

namespace std {
template <>
struct hash<SPF::Result> {
  size_t operator()(SPF::Result const& x) const
  {
    return static_cast<size_t>(x);
  }
};
}

namespace SPF {
inline std::ostream& operator<<(std::ostream& s, Result result)
{
  return s << result_to_string[result];
}
}

#endif // SPF_DOT_HPP

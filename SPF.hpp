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

#include <arpa/inet.h> // in_addr required by spf2/spf.h

extern "C" {
#include <spf2/spf.h>
}

#include <glog/logging.h>

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

std::ostream& operator<<(std::ostream& os, Result result);

class Server {
public:
  Server(Server const&) = delete;
  Server& operator=(Server const&) = delete;

  explicit Server(char const* fqdn)
    : srv_(CHECK_NOTNULL(SPF_server_new(SPF_DNS_RESOLV, 1)))
  {
    CHECK_EQ(SPF_E_SUCCESS, SPF_server_set_rec_dom(srv_, CHECK_NOTNULL(fqdn)));
  }
  ~Server() { SPF_server_free(srv_); }

private:
  SPF_server_t* srv_{nullptr};

  friend class Request;
};

class Request {
public:
  Request(Request const&) = delete;
  Request& operator=(Request const&) = delete;

  explicit Request(Server const& srv)
    : req_(CHECK_NOTNULL(SPF_request_new(srv.srv_)))
  {
  }
  ~Request() { SPF_request_free(req_); }
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
  SPF_request_t* req_{nullptr};

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
    CHECK_NOTNULL(res_);
  }
  ~Response() { SPF_response_free(res_); }
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
  SPF_response_t* res_{nullptr};
};

} // namespace SPF

#endif // SPF_DOT_HPP

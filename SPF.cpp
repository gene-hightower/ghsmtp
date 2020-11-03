#include "SPF.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <arpa/inet.h> // in_addr required by spf2/spf.h
#include <arpa/nameser.h>

extern "C" {
#define HAVE_NS_TYPE
#include <spf2/spf.h>
}

namespace SPF {

// clang-format off
Result::Result(int value)
{
  switch (value) {
  case SPF_RESULT_INVALID:   value_ = INVALID;   break;
  case SPF_RESULT_NEUTRAL:   value_ = NEUTRAL;   break;
  case SPF_RESULT_PASS:      value_ = PASS;      break;
  case SPF_RESULT_FAIL:      value_ = FAIL;      break;
  case SPF_RESULT_SOFTFAIL:  value_ = SOFTFAIL;  break;
  case SPF_RESULT_NONE:      value_ = NONE;      break;
  case SPF_RESULT_TEMPERROR: value_ = TEMPERROR; break;
  case SPF_RESULT_PERMERROR: value_ = PERMERROR; break;
  default:
    LOG(ERROR) << "unrecognized SPF_result_t value: " << value;
  }
}

char const* Result::c_str(value_t value)
{
  switch (value) {
  case INVALID:   return "invalid";
  case NEUTRAL:   return "neutral";
  case PASS:      return "pass";
  case FAIL:      return "fail";
  case SOFTFAIL:  return "softfail";
  case NONE:      return "none";
  case TEMPERROR: return "temperror";
  case PERMERROR: return "permerror";
  }
  LOG(ERROR) << "unknown Result value";
  return "** unknown **";
}
// clang-format on

std::ostream& operator<<(std::ostream& os, Result result)
{
  return os << result.c_str();
}

std::ostream& operator<<(std::ostream& os, Result::value_t result)
{
  return os << Result::c_str(result);
}

Server::Server(char const* fqdn)
  : srv_(CHECK_NOTNULL(SPF_server_new(SPF_DNS_RESOLV, 1)))
{
  CHECK_EQ(SPF_E_SUCCESS, SPF_server_set_rec_dom(srv_, CHECK_NOTNULL(fqdn)));
}

Server::~Server()
{
  if (srv_)
    SPF_server_free(srv_);
}

Server::initializer::initializer()
{
  // Hook info libspf2's error procs.
  SPF_error_handler   = log_error_;
  SPF_warning_handler = log_warning_;
  SPF_info_handler    = log_info_;
  SPF_debug_handler   = nullptr;
}

Request::Request(Server const& srv)
  : req_(CHECK_NOTNULL(SPF_request_new(srv.srv_)))
{
}

Request::~Request()
{
  if (req_)
    SPF_request_free(req_);
}

void Request::set_ip_str(char const* ip)
{
  if (IP4::is_address(ip)) {
    set_ipv4_str(ip);
  }
  else if (IP6::is_address(ip)) {
    set_ipv6_str(ip);
  }
  else {
    LOG(FATAL) << "non IP address passed to set_ip_str: " << ip;
  }
}
void Request::set_ipv4_str(char const* ipv4)
{
  CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_ipv4_str(req_, ipv4));
}
void Request::set_ipv6_str(char const* ipv6)
{
  CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_ipv6_str(req_, ipv6));
}
void Request::set_helo_dom(char const* dom)
{
  CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_helo_dom(req_, dom));
}
void Request::set_env_from(char const* frm)
{
  CHECK_EQ(SPF_E_SUCCESS, SPF_request_set_env_from(req_, frm));
}

char const* Request::get_sender_dom() const
{
  auto sender_dom = req_->env_from_dp;
  if (sender_dom == nullptr)
    sender_dom = req_->helo_dom;
  return sender_dom;
}

Response::Response(Request const& req)
{
  // We ignore the return code from this call, as everything we need
  // to know is in the SPF_response_t struct.
  SPF_request_query_mailfrom(req.req_, &res_);
  CHECK_NOTNULL(res_);
}

Response::~Response()
{
  if (res_)
    SPF_response_free(res_);
}

Result Response::result() const { return Result(SPF_response_result(res_)); }

char const* Response::smtp_comment() const
{
  return SPF_response_get_smtp_comment(res_);
}

char const* Response::header_comment() const
{
  return SPF_response_get_header_comment(res_);
}

char const* Response::received_spf() const
{
  return SPF_response_get_received_spf(res_);
}
} // namespace SPF

SPF::Server::initializer SPF::Server::init;

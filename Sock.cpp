#include "Sock.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <glog/logging.h>

using namespace std::string_literals;

Sock::Sock(int fd_in,
           int fd_out,
           std::function<void(void)> read_hook,
           std::chrono::milliseconds read_timeout,
           std::chrono::milliseconds write_timeout,
           std::chrono::milliseconds starttls_timeout)
  : iostream_(
        fd_in, fd_out, read_hook, read_timeout, write_timeout, starttls_timeout)
{
  // Get our local IP address as "us".

  if (-1 == getsockname(fd_in, &us_addr_.addr, &us_addr_len_)) {
    // Ignore ENOTSOCK errors from getsockname, useful for testing.
    PLOG_IF(WARNING, ENOTSOCK != errno) << "getsockname failed";
  }
  else {
    switch (us_addr_len_) {
    case sizeof(sockaddr_in):
      PCHECK(inet_ntop(AF_INET, &us_addr_.addr_in.sin_addr, us_addr_str_,
                       sizeof us_addr_str_)
             != nullptr);
      us_address_literal_ = "["s + us_addr_str_ + "]"s;
      break;
    case sizeof(sockaddr_in6):
      PCHECK(inet_ntop(AF_INET6, &us_addr_.addr_in6.sin6_addr, us_addr_str_,
                       sizeof us_addr_str_)
             != nullptr);
      us_address_literal_ = "[IPv6:"s + us_addr_str_ + "]"s;
      break;
    default:
      LOG(FATAL) << "bogus address length (" << us_addr_len_
                 << ") returned from getsockname";
    }
  }

  // Get the remote IP address as "them".

  if (-1 == getpeername(fd_out, &them_addr_.addr, &them_addr_len_)) {
    // Ignore ENOTSOCK errors from getpeername, useful for testing.
    PLOG_IF(WARNING, ENOTSOCK != errno) << "getpeername failed";
  }
  else {
    switch (them_addr_len_) {
    case sizeof(sockaddr_in):
      PCHECK(inet_ntop(AF_INET, &them_addr_.addr_in.sin_addr, them_addr_str_,
                       sizeof them_addr_str_)
             != nullptr);
      them_address_literal_ = IP4::to_address_literal(them_addr_str_);
      break;

    case sizeof(sockaddr_in6):
      PCHECK(inet_ntop(AF_INET6, &them_addr_.addr_in6.sin6_addr, them_addr_str_,
                       sizeof them_addr_str_)
             != nullptr);
      them_address_literal_ = IP6::to_address_literal(them_addr_str_);
      break;

    default:
      LOG(FATAL) << "bogus address length (" << them_addr_len_
                 << ") returned from getpeername";
    }
  }
}

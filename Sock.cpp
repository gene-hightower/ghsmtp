#include "Sock.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <glog/logging.h>

static bool is_ipv4_mapped_ipv6_addresses(in6_addr const& sa)
{
  // clang-format off
  return sa.s6_addr[0] == 0 &&
         sa.s6_addr[1] == 0 &&
         sa.s6_addr[2] == 0 &&
         sa.s6_addr[3] == 0 &&
         sa.s6_addr[4] == 0 &&
         sa.s6_addr[5] == 0 &&
         sa.s6_addr[6] == 0 &&
         sa.s6_addr[7] == 0 &&
         sa.s6_addr[8] == 0 &&
         sa.s6_addr[9] == 0 &&
         sa.s6_addr[10] == 0xff &&
         sa.s6_addr[11] == 0xff;
  // clang-format on
}

Sock::Sock(int                       fd_in,
           int                       fd_out,
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
      us_address_literal_ = IP4::to_address_literal(us_addr_str_);
      break;
    case sizeof(sockaddr_in6):
      PCHECK(inet_ntop(AF_INET6, &us_addr_.addr_in6.sin6_addr, us_addr_str_,
                       sizeof us_addr_str_)
             != nullptr);
      us_address_literal_ = IP6::to_address_literal(us_addr_str_);
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
      if (is_ipv4_mapped_ipv6_addresses(them_addr_.addr_in6.sin6_addr)) {
        PCHECK(inet_ntop(AF_INET, &them_addr_.addr_in6.sin6_addr.s6_addr[12],
                         them_addr_str_, sizeof them_addr_str_)
               != nullptr);
        them_address_literal_ = IP4::to_address_literal(them_addr_str_);
        LOG(INFO) << "IPv4 disguised as IPv6: " << them_addr_str_;
      }
      else {
        PCHECK(inet_ntop(AF_INET6, &them_addr_.addr_in6.sin6_addr,
                         them_addr_str_, sizeof them_addr_str_)
               != nullptr);
        them_address_literal_ = IP6::to_address_literal(them_addr_str_);
      }
      break;

    default:
      LOG(FATAL) << "bogus address length (" << them_addr_len_
                 << ") returned from getpeername";
    }
  }
}

#include "Sock.hpp"

Sock::Sock(int fd_in, int fd_out)
  : iostream_(fd_in, fd_out)
{
  // Get our local IP address as "us".

  if (-1 == getsockname(fd_in, reinterpret_cast<struct sockaddr*>(&us_addr_),
                        &us_addr_len_)) {
    // Ignore ENOTSOCK errors from getsockname, useful for testing.
    PLOG_IF(WARNING, ENOTSOCK != errno) << "getsockname failed";
  }
  else {
    switch (us_addr_len_) {
    case sizeof(sockaddr_in):
      PCHECK(inet_ntop(
                 AF_INET,
                 &(reinterpret_cast<struct sockaddr_in*>(&us_addr_)->sin_addr),
                 us_addr_str_, sizeof us_addr_str_)
             != nullptr);
      us_address_literal_ = "["s + us_addr_str_ + "]"s;
      break;
    case sizeof(sockaddr_in6):
      PCHECK(
          inet_ntop(
              AF_INET6,
              &(reinterpret_cast<struct sockaddr_in6*>(&us_addr_)->sin6_addr),
              us_addr_str_, sizeof us_addr_str_)
          != nullptr);
      us_address_literal_ = "[IPv6:"s + us_addr_str_ + "]"s;
      break;
    default:
      LOG(FATAL) << "bogus address length (" << us_addr_len_
                 << ") returned from getsockname";
    }
  }

  // Get the remote IP address as "them".

  if (-1 == getpeername(fd_out, reinterpret_cast<struct sockaddr*>(&them_addr_),
                        &them_addr_len_)) {
    // Ignore ENOTSOCK errors from getpeername, useful for testing.
    PLOG_IF(WARNING, ENOTSOCK != errno) << "getpeername failed";
  }
  else {
    switch (them_addr_len_) {
    case sizeof(sockaddr_in):
      PCHECK(
          inet_ntop(
              AF_INET,
              &(reinterpret_cast<struct sockaddr_in*>(&them_addr_)->sin_addr),
              them_addr_str_, sizeof them_addr_str_)
          != nullptr);
      them_address_literal_ = "["s + them_addr_str_ + "]"s;
      break;
    case sizeof(sockaddr_in6):
      PCHECK(
          inet_ntop(
              AF_INET6,
              &(reinterpret_cast<struct sockaddr_in6*>(&them_addr_)->sin6_addr),
              them_addr_str_, sizeof them_addr_str_)
          != nullptr);
      them_address_literal_ = "[IPv6:"s + them_addr_str_ + "]"s;
      break;
    default:
      LOG(FATAL) << "bogus address length (" << them_addr_len_
                 << ") returned from getpeername";
    }
  }
}

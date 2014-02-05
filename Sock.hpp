/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

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

#ifndef SOCK_DOT_HPP
#define SOCK_DOT_HPP

#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <unistd.h>

#include "Logging.hpp"
#include "SockBuffer.hpp"

class Sock {
public:
  Sock(const Sock&) = delete;
  Sock& operator=(const Sock&) = delete;

  Sock(int fd_in, int fd_out)
    : buf_source_(fd_in)
    , buf_sink_(fd_out)
    , istream_(buf_source_)
    , ostream_(buf_sink_)
    , us_addr_len_(sizeof us_addr_)
    , them_addr_len_(sizeof them_addr_)
    , us_addr_str_{ '\0' }
    , them_addr_str_{ '\0' }
  {
    // Get our local IP address as "us".

    if (-1 != getsockname(fd_in, reinterpret_cast<struct sockaddr*>(&us_addr_),
                          &us_addr_len_)) {
      switch (us_addr_len_) {
      case sizeof(sockaddr_in) :
        PCHECK(inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in*>(
                                       &us_addr_)->sin_addr),
                         us_addr_str_, sizeof us_addr_str_) != nullptr);
        break;
      case sizeof(sockaddr_in6) :
        PCHECK(inet_ntop(AF_INET6, &(reinterpret_cast<struct sockaddr_in6*>(
                                        &us_addr_)->sin6_addr),
                         us_addr_str_, sizeof us_addr_str_) != nullptr);
        break;
      default:
        SYSLOG(ERROR) << "bogus address length (" << us_addr_len_
                      << ") returned from getsockname";
      }
    } else {
      CHECK_EQ(ENOTSOCK, errno); // only acceptable error from getsockname
    }

    // Get the remote IP address as "them".

    if (-1 != getpeername(fd_out,
                          reinterpret_cast<struct sockaddr*>(&them_addr_),
                          &them_addr_len_)) {
      switch (them_addr_len_) {
      case sizeof(sockaddr_in) :
        PCHECK(inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in*>(
                                       &them_addr_)->sin_addr),
                         them_addr_str_, sizeof them_addr_str_) != nullptr);
        break;
      case sizeof(sockaddr_in6) :
        PCHECK(inet_ntop(AF_INET6, &(reinterpret_cast<struct sockaddr_in6*>(
                                        &them_addr_)->sin6_addr),
                         them_addr_str_, sizeof them_addr_str_) != nullptr);
        break;
      default:
        SYSLOG(ERROR) << "bogus address length (" << them_addr_len_
                      << ") returned from getpeername";
      }
    } else {
      // Ignore ENOTSOCK errors from getpeername, useful for testing.
      PLOG_IF(WARNING, ENOTSOCK != errno) << "getpeername failed";
    }
  }

  char const* us_c_str() const
  {
    return us_addr_str_;
  }
  char const* them_c_str() const
  {
    return them_addr_str_;
  }
  bool has_peername() const
  {
    return them_addr_str_[0] != '\0';
  }
  bool input_pending(std::chrono::milliseconds wait)
  {
    return istream_->input_pending(wait);
  }
  bool timed_out()
  {
    return istream_->timed_out();
  }
  std::istream& in()
  {
    return istream_;
  }
  std::ostream& out()
  {
    return ostream_;
  }

private:
  SockBufferSource buf_source_;
  SockBufferSink buf_sink_;

  boost::iostreams::stream<SockBufferSource> istream_;
  boost::iostreams::stream<SockBufferSink> ostream_;

  socklen_t us_addr_len_;
  socklen_t them_addr_len_;

  sockaddr_storage us_addr_;
  sockaddr_storage them_addr_;

  char us_addr_str_[INET6_ADDRSTRLEN];
  char them_addr_str_[INET6_ADDRSTRLEN];
};

#endif // SOCK_DOT_HPP

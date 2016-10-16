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

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <unistd.h>

#include "SockDevice.hpp"
#include <glog/logging.h>

class Sock {
public:
  Sock(const Sock&) = delete;
  Sock& operator=(const Sock&) = delete;

  Sock(int fd_in, int fd_out)
    : sock_(fd_in, fd_out)
  {
    sockaddr_storage us_addr;
    sockaddr_storage them_addr;

    socklen_t us_addr_len = sizeof us_addr;
    socklen_t them_addr_len = sizeof them_addr;

    // Get our local IP address as "us".

    if (-1 != getsockname(fd_in, reinterpret_cast<struct sockaddr*>(&us_addr),
                          &us_addr_len)) {
      switch (us_addr_len) {
      case sizeof(sockaddr_in):
        PCHECK(inet_ntop(
                   AF_INET,
                   &(reinterpret_cast<struct sockaddr_in*>(&us_addr)->sin_addr),
                   us_addr_str_, sizeof us_addr_str_)
               != nullptr);
        break;
      case sizeof(sockaddr_in6):
        LOG(WARNING)
            << "getsockname returned us_addr_len == sizeof(sockaddr_in6)";
        PCHECK(
            inet_ntop(
                AF_INET6,
                &(reinterpret_cast<struct sockaddr_in6*>(&us_addr)->sin6_addr),
                us_addr_str_, sizeof us_addr_str_)
            != nullptr);
        break;
      default:
        LOG(ERROR) << "bogus address length (" << us_addr_len
                   << ") returned from getsockname";
      }
    }
    else {
      CHECK_EQ(ENOTSOCK, errno); // only acceptable error from getsockname
    }

    // Get the remote IP address as "them".

    if (-1 != getpeername(fd_out,
                          reinterpret_cast<struct sockaddr*>(&them_addr),
                          &them_addr_len)) {
      switch (them_addr_len) {
      case sizeof(sockaddr_in):
        PCHECK(
            inet_ntop(
                AF_INET,
                &(reinterpret_cast<struct sockaddr_in*>(&them_addr)->sin_addr),
                them_addr_str_, sizeof them_addr_str_)
            != nullptr);
        break;
      case sizeof(sockaddr_in6):
        LOG(WARNING)
            << "getpeername returned them_addr_len == sizeof(sockaddr_in6)";
        PCHECK(inet_ntop(AF_INET6,
                         &(reinterpret_cast<struct sockaddr_in6*>(&them_addr)
                               ->sin6_addr),
                         them_addr_str_, sizeof them_addr_str_)
               != nullptr);
        break;
      default:
        LOG(ERROR) << "bogus address length (" << them_addr_len
                   << ") returned from getpeername";
      }
    }
    else {
      // Ignore ENOTSOCK errors from getpeername, useful for testing.
      PLOG_IF(WARNING, ENOTSOCK != errno) << "getpeername failed";
    }
  }

  char const* us_c_str() const { return us_addr_str_; }
  char const* them_c_str() const { return them_addr_str_; }
  bool has_peername() const { return them_addr_str_[0] != '\0'; }
  bool input_ready(std::chrono::milliseconds wait)
  {
    return sock_->input_ready(wait);
  }
  bool timed_out() { return sock_->timed_out(); }

  std::streamsize read(char* s, std::streamsize n)
  {
    sock_.peek(); // buffer up some input
    return sock_.readsome(s, n);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    sock_.write(s, n);
    return n;
  }

  void starttls() { sock_->starttls(); }
  bool tls() { return sock_->tls(); }
  std::string tls_info() { return sock_->tls_info(); }

private:
  boost::iostreams::stream<SockDevice> sock_;

  char us_addr_str_[INET6_ADDRSTRLEN]{'\0'};
  char them_addr_str_[INET6_ADDRSTRLEN]{'\0'};
};

#endif // SOCK_DOT_HPP

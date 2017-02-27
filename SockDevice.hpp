/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#ifndef SOCKDEVICE_DOT_HPP
#define SOCKDEVICE_DOT_HPP

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <streambuf>
#include <string>

#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"

#include <glog/logging.h>

namespace Config {
// Read timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout = std::chrono::minutes(5);
constexpr auto write_timeout = std::chrono::seconds(10);
constexpr auto starttls_timeout = std::chrono::seconds(10);
}

class SockDevice {
public:
  SockDevice& operator=(const SockDevice&) = delete;
  SockDevice(const SockDevice& that) = delete;

  SockDevice(int fd_in, int fd_out)
    : fd_in_(fd_in)
    , fd_out_(fd_out)
  {
    POSIX::set_nonblocking(fd_in_);
    POSIX::set_nonblocking(fd_out_);
  }
  bool input_ready(std::chrono::milliseconds wait) const
  {
    return POSIX::input_ready(fd_in_, wait);
  }
  bool output_ready(std::chrono::milliseconds wait) const
  {
    return POSIX::output_ready(fd_out_, wait);
  }
  bool timed_out() const { return timed_out_; }
  std::streamsize read(char* s, std::streamsize n)
  {
    return tls_active_
               ? tls_.read(s, n, Config::read_timeout, timed_out_)
               : POSIX::read(fd_in_, s, n, Config::read_timeout, timed_out_);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    return tls_active_
               ? tls_.write(s, n, Config::write_timeout, timed_out_)
               : POSIX::write(fd_out_, s, n, Config::write_timeout, timed_out_);
  }
  void starttls()
  {
    tls_.starttls(fd_in_, fd_out_, Config::starttls_timeout);
    tls_active_ = true;
  }
  std::string tls_info()
  {
    if (tls_active_) {
      return tls_.info();
    }
    return "";
  }
  bool tls() { return tls_active_; }

private:
  int fd_in_;
  int fd_out_;

  bool timed_out_{false};

  TLS tls_;
  bool tls_active_{false};
};

#endif // SOCKDEVICE_DOT_HPP

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

#ifndef SOCKBUFFER_DOT_HPP
#define SOCKBUFFER_DOT_HPP

#include <cerrno>
#include <chrono>
#include <cstring> // std::strerror
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>

#include <fcntl.h>
#include <sys/select.h>

#include "Logging.hpp"

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>

namespace Config {
// Timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout = std::chrono::minutes(5);
}

class read_error : public std::runtime_error {
public:
  explicit read_error(int e) : std::runtime_error(errno_to_str(e))
  {
  }

private:
  static std::string errno_to_str(int e)
  {
    std::stringstream ss;
    ss << "read() error errno==" << e << ": " << std::strerror(e);
    return ss.str();
  }
};

class SockBuffer
    : public boost::iostreams::device<boost::iostreams::bidirectional> {
public:
  explicit SockBuffer(int fd_in, int fd_out)
    : fd_in_(fd_in)
    , fd_out_(fd_out)
    , timed_out_(false)
  {
    int flags;
    PCHECK((flags = fcntl(fd_in_, F_GETFL, 0)) != -1);
    PCHECK(fcntl(fd_in_, F_SETFL, flags | O_NONBLOCK) != -1);
  }
  bool input_pending(std::chrono::milliseconds wait) const
  {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd_in_, &rfds);

    struct timeval tv;
    tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
    tv.tv_usec = (wait.count() % 1000) * 1000;

    int inputs;
    PCHECK((inputs = select(fd_in_ + 1, &rfds, NULL, NULL, &tv)) != -1);

    return 0 != inputs;
  }
  bool timed_out() const
  {
    return timed_out_;
  }
  std::streamsize read(char* s, std::streamsize n)
  {
    std::chrono::time_point<std::chrono::system_clock> start =
        std::chrono::system_clock::now();

    ssize_t n_read;
    while ((n_read = ::read(fd_in_, static_cast<void*>(s),
                            static_cast<size_t>(n))) < 0) {

      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {

        std::chrono::time_point<std::chrono::system_clock> now =
            std::chrono::system_clock::now();

        if (now < (start + Config::read_timeout))
          if (input_pending(
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      (start + Config::read_timeout) - now)))
            continue;

        timed_out_ = true;
        return static_cast<std::streamsize>(-1);
      }

      if (errno == EINTR)
        continue;

      throw read_error(errno);
    }

    if (n_read == 0)
      return static_cast<std::streamsize>(-1);

    return static_cast<std::streamsize>(n_read);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    return ::write(fd_out_, static_cast<const void*>(s),
                   static_cast<size_t>(n));
  }
  void starttls()
  {
  }

private:
  int fd_in_;
  int fd_out_;

  bool timed_out_;
};

#endif // SOCKBUFFER_DOT_HPP

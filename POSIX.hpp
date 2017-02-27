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

#ifndef POSIX_DOT_HPP
#define POSIX_DOT_HPP

#include <chrono>
#include <functional>

#include <unistd.h>

class POSIX {
public:
  POSIX() = delete;
  POSIX(POSIX const&) = delete;

  static void set_nonblocking(int fd);

  static bool input_ready(int fd_in, std::chrono::milliseconds wait);
  static bool output_ready(int fd_out, std::chrono::milliseconds wait);

  static std::streamsize read(int fd_in,
                              char* s,
                              std::streamsize n,
                              std::chrono::milliseconds timeout,
                              bool& t_o)
  {
    return io_fd_("read", ::read, fd_in, s, n, timeout, t_o);
  }

  static std::streamsize write(int fd_out,
                               const char* s,
                               std::streamsize n,
                               std::chrono::milliseconds timeout,
                               bool& t_o)
  {
    return io_fd_("write", ::write, fd_out, const_cast<char*>(s), n, timeout,
                  t_o);
  }

private:
  static std::streamsize io_fd_(char const* fnm,
                                std::function<ssize_t(int, void*, size_t)> fnc,
                                int fd,
                                char* s,
                                std::streamsize n,
                                std::chrono::milliseconds timeout,
                                bool& t_o);
};

#endif // POSIX_DOT_HPP

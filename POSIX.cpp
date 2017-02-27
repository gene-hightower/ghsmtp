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

#include "POSIX.hpp"

#include <glog/logging.h>

#include <fcntl.h>
#include <sys/select.h>

void POSIX::set_nonblocking(int fd)
{
  int flags;
  PCHECK((flags = fcntl(fd, F_GETFL, 0)) != -1);
  if (0 == (flags & O_NONBLOCK)) {
    PCHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1);
  }
}

bool POSIX::input_ready(int fd_in, std::chrono::milliseconds wait)
{
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd_in, &fds);

  struct timeval tv;
  tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
  tv.tv_usec = (wait.count() % 1000) * 1000;

  int puts;
  PCHECK((puts = select(fd_in + 1, &fds, nullptr, nullptr, &tv)) != -1);

  return 0 != puts;
}

bool POSIX::output_ready(int fd_out, std::chrono::milliseconds wait)
{
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd_out, &fds);

  struct timeval tv;
  tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
  tv.tv_usec = (wait.count() % 1000) * 1000;

  int puts;
  PCHECK((puts = select(fd_out + 1, nullptr, &fds, nullptr, &tv)) != -1);

  return 0 != puts;
}

std::streamsize POSIX::io_fd_(char const* fnm,
                              std::function<ssize_t(int, void*, size_t)> fnc,
                              int fd,
                              char* s,
                              std::streamsize n,
                              std::chrono::milliseconds timeout,
                              bool& t_o)
{
  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  ssize_t n_ret;
  while ((n_ret = fnc(fd, static_cast<void*>(s), static_cast<size_t>(n))) < 0) {

    if (errno == EINTR)
      continue; // try fnc again

    PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN))
        << "Error from POSIX " << fnm << " system call";

    time_point<system_clock> now = system_clock::now();
    if (now < (start + timeout)) {
      milliseconds time_left
          = duration_cast<milliseconds>((start + timeout) - now);
      if (input_ready(fd, time_left))
        continue; // try fnc again
    }
    t_o = true;
    LOG(WARNING) << fnm << " timed out";
    return static_cast<std::streamsize>(-1);
  }

  if (0 == n_ret) { // This happens for "normal" files.
    LOG(WARNING) << fnm << " returned zero, interpreting as EOF";
    return static_cast<std::streamsize>(-1);
  }

  return static_cast<std::streamsize>(n_ret);
}

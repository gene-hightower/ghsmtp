/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

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

#include "POSIX.hpp"

#include <functional>

#include <fcntl.h>
#include <sys/select.h>

#include "Logging.hpp"

namespace POSIX {

void set_nonblocking(int fd)
{
  int flags;
  PCHECK((flags = fcntl(fd, F_GETFL, 0)) != -1);
  if (0 == (flags & O_NONBLOCK)) {
    PCHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1);
  }
}

bool input_ready(int fd_in, std::chrono::milliseconds wait)
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

bool output_ready(int fd_out, std::chrono::milliseconds wait)
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

static std::streamsize io_fd(char const* fnm,
                             std::function<ssize_t(int, void*, size_t)> fnc,
                             int fd, char* s, std::streamsize n,
                             std::chrono::milliseconds timeout, bool& t_o)
{
  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  ssize_t n_ret;
  while ((n_ret = fnc(fd, static_cast<void*>(s), static_cast<size_t>(n))) < 0) {

    if (errno == EINTR)
      continue; // try fnc again

    PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN));

    time_point<system_clock> now = system_clock::now();
    if (now < (start + timeout)) {
      milliseconds time_left =
          duration_cast<milliseconds>((start + timeout) - now);
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
std::streamsize read(int fd_in, char* s, std::streamsize n,
                     std::chrono::milliseconds timeout, bool& t_o)
{
  return io_fd("read", ::read, fd_in, s, n, timeout, t_o);
}
std::streamsize write(int fd_out, const char* s, std::streamsize n,
                      std::chrono::milliseconds timeout, bool& t_o)
{
  return io_fd("write", ::write, fd_out, const_cast<char*>(s), n, timeout, t_o);
}
}

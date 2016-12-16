/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
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

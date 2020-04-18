#ifndef POSIX_DOT_HPP
#define POSIX_DOT_HPP

#include <chrono>
#include <functional>
#include <ios>

#include <unistd.h>

constexpr void null_hook(void) {}

class POSIX {
public:
  POSIX()             = delete;
  POSIX(POSIX const&) = delete;

  static void set_nonblocking(int fd);

  static bool input_ready(int fd_in, std::chrono::milliseconds wait);
  static bool output_ready(int fd_out, std::chrono::milliseconds wait);

  static std::streamsize read(int                       fd,
                              char*                     s,
                              std::streamsize           n,
                              std::function<void(void)> read_hook,
                              std::chrono::milliseconds timeout,
                              bool&                     t_o);

  static std::streamsize write(int                       fd,
                               const char*               s,
                               std::streamsize           n,
                               std::chrono::milliseconds timeout,
                               bool&                     t_o);
};

#endif // POSIX_DOT_HPP

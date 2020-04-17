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

  static std::streamsize read(int                       fd_in,
                              char*                     s,
                              std::streamsize           n,
                              std::function<void(void)> read_hook,
                              std::chrono::milliseconds timeout,
                              bool&                     t_o)
  {
    return read_fd_(std::chrono::system_clock::now(), read_hook, fd_in, s, n,
                    timeout, t_o);
  }

  static std::streamsize write(int                       fd_out,
                               const char*               s,
                               std::streamsize           n,
                               std::chrono::milliseconds timeout,
                               bool&                     t_o)
  {
    return write_fd_(std::chrono::system_clock::now(), fd_out, s, n, timeout,
                     t_o);
  }

private:
  static std::streamsize
  read_fd_(std::chrono::time_point<std::chrono::system_clock> start,
           std::function<void(void)>                          read_hook,
           int                                                fd,
           char*                                              s,
           std::streamsize                                    n,
           std::chrono::milliseconds                          timeout,
           bool&                                              t_o);

  static std::streamsize
  write_fd_(std::chrono::time_point<std::chrono::system_clock> start,
            int                                                fd,
            char const*                                        s,
            std::streamsize                                    n,
            std::chrono::milliseconds                          timeout,
            bool&                                              t_o);
};

#endif // POSIX_DOT_HPP

#ifndef POSIX_DOT_HPP
#define POSIX_DOT_HPP

#include <chrono>
#include <functional>

#include <unistd.h>

namespace {
void null_hook(void) {}
} // namespace

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
                              std::function<void(void)> read_hook,
                              std::chrono::milliseconds timeout,
                              bool& t_o)
  {
    return io_fd_("read", std::chrono::system_clock::now(), ::read, input_ready,
                  read_hook, fd_in, s, n, timeout, t_o);
  }

  static std::streamsize write(int fd_out,
                               const char* c_s,
                               std::streamsize n,
                               std::chrono::milliseconds timeout,
                               bool& t_o)
  {
    auto s = const_cast<char*>(c_s);
    return io_fd_("write", std::chrono::system_clock::now(), ::write,
                  output_ready, null_hook, fd_out, s, n, timeout, t_o);
  }

private:
  static std::streamsize
  io_fd_(char const* fnm,
         std::chrono::time_point<std::chrono::system_clock> start,
         std::function<ssize_t(int, void*, size_t)> io_fnc,
         std::function<bool(int, std::chrono::milliseconds)> rdy_fnc,
         std::function<void(void)> read_hook,
         int fd,
         char* s,
         std::streamsize n,
         std::chrono::milliseconds timeout,
         bool& t_o);
};

#endif // POSIX_DOT_HPP

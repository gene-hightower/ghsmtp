#include "POSIX.hpp"

#include <glog/logging.h>

#include <fcntl.h>
#include <sys/select.h>

using namespace std::chrono;

void POSIX::set_nonblocking(int fd)
{
  int flags;
  PCHECK((flags = fcntl(fd, F_GETFL, 0)) != -1);
  if (0 == (flags & O_NONBLOCK)) {
    PCHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1);
  }
}

bool POSIX::input_ready(int fd_in, milliseconds wait)
{
  auto fds{fd_set{}};
  FD_ZERO(&fds);
  FD_SET(fd_in, &fds);

  auto tv{(struct timeval){}};
  tv.tv_sec = duration_cast<seconds>(wait).count();
  tv.tv_usec = (wait.count() % 1000) * 1000;

  int puts;
  PCHECK((puts = select(fd_in + 1, &fds, nullptr, nullptr, &tv)) != -1);

  return 0 != puts;
}

bool POSIX::output_ready(int fd_out, milliseconds wait)
{
  auto fds{fd_set{}};
  FD_ZERO(&fds);
  FD_SET(fd_out, &fds);

  auto tv{(struct timeval){}};
  tv.tv_sec = duration_cast<seconds>(wait).count();
  tv.tv_usec = (wait.count() % 1000) * 1000;

  int puts;
  PCHECK((puts = select(fd_out + 1, nullptr, &fds, nullptr, &tv)) != -1);

  return 0 != puts;
}

std::streamsize POSIX::io_fd_(char const* fnm,
                              time_point<system_clock> start,
                              std::function<ssize_t(int, void*, size_t)> io_fnc,
                              std::function<bool(int, milliseconds)> rdy_fnc,
                              std::function<void(void)> read_hook,
                              int fd,
                              char* s,
                              std::streamsize n,
                              milliseconds timeout,
                              bool& t_o)
{
  auto end_time = start + timeout;

  ssize_t n_ret;
  while ((n_ret = io_fnc(fd, static_cast<void*>(s), static_cast<size_t>(n)))
         < 0) {

    if (errno == EINTR)
      continue; // try io_fnc again

    if (errno == ECONNRESET) {
      LOG(WARNING) << fnm << " raised ECONNRESET, interpreting as EOF";
      return static_cast<std::streamsize>(-1);
    }

    PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN))
        << "Error from POSIX " << fnm << " system call";

    auto now = system_clock::now();
    if (now < end_time) {
      auto time_left = duration_cast<milliseconds>(end_time - now);
      if (*fnm == 'r') {
        read_hook();
      }
      if (rdy_fnc(fd, time_left))
        continue; // try io_fnc again
    }
    t_o = true;
    LOG(WARNING) << fnm << " timed out";
    return static_cast<std::streamsize>(-1);
  }

  if (0 == n_ret) { // This happens for "normal" files.
    LOG(WARNING) << fnm << " returned zero";
    // return static_cast<std::streamsize>(-1);
  }

  // The stream buffer code above us can deal with a short read, but
  // not a short write.

  while ((*fnm == 'w') && n_ret && (n_ret < n)) {
    auto next_n = io_fd_(fnm, start, io_fnc, rdy_fnc, read_hook, fd, s + n_ret,
                         n - n_ret, timeout, t_o);
    if (next_n == -1)
      break;
    n_ret += next_n;
  }

  return n_ret;
}

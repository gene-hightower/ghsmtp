#include "POSIX.hpp"

#include <glog/logging.h>

#include <fcntl.h>
#include <sys/select.h>

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;
using std::chrono::time_point;

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

  auto tv{timeval{}};
  tv.tv_sec  = duration_cast<seconds>(wait).count();
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

  auto tv{timeval{}};
  tv.tv_sec  = duration_cast<seconds>(wait).count();
  tv.tv_usec = (wait.count() % 1000) * 1000;

  int puts;
  PCHECK((puts = select(fd_out + 1, nullptr, &fds, nullptr, &tv)) != -1);

  return 0 != puts;
}

std::streamsize POSIX::read(int                       fd,
                            char*                     s,
                            std::streamsize           n,
                            std::function<void(void)> read_hook,
                            std::chrono::milliseconds timeout,
                            bool&                     t_o)
{
  auto const start    = std::chrono::system_clock::now();
  auto const end_time = start + timeout;

  for (;;) {
    auto const n_ret = ::read(fd, static_cast<void*>(s), n);

    if (n_ret == -1) {
      switch (errno) {
      case EINTR: break; // try read again

      case ECONNRESET:
        LOG(WARNING) << "read(2) raised ECONNRESET";
        return -1;

      default:
        PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN))
            << "error from read(2)";
      }
    }
    else if (n_ret >= 0) {
      return n_ret;
    }

    auto const now = system_clock::now();
    if (now < end_time) {
      auto const time_left = duration_cast<milliseconds>(end_time - now);
      read_hook();
      if (input_ready(fd, time_left))
        continue; // try read again
    }
    t_o = true;
    LOG(WARNING) << "read(2) timed out";
    return -1;
  }
}

std::streamsize POSIX::write(int                       fd,
                             const char*               s,
                             std::streamsize           n,
                             std::chrono::milliseconds timeout,
                             bool&                     t_o)
{
  auto const start    = std::chrono::system_clock::now();
  auto const end_time = start + timeout;

  auto written = std::streamsize{};

  for (;;) {
    auto const n_ret = ::write(fd, static_cast<const void*>(s), n - written);

    if (n_ret == -1) {
      switch (errno) {
      case EINTR: break; // try write again

      case ECONNRESET:
        LOG(WARNING) << "write(2) raised ECONNRESET";
        return -1;

      default:
        PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN))
            << "error from write(2)";
      }
    }
    else {
      s += n_ret;
      written += n_ret;
    }

    if (written == n)
      return n;

    auto const now = system_clock::now();
    if (now < end_time) {
      auto const time_left = duration_cast<milliseconds>(end_time - now);
      if (output_ready(fd, time_left))
        continue; // write some more
    }
    t_o = true;
    LOG(WARNING) << "write(2) time out";
    return -1;
  }
}

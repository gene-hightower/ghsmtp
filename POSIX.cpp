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

std::streamsize POSIX::read_fd_(time_point<system_clock>  start,
                                std::function<void(void)> read_hook,
                                int                       fd,
                                char*                     s,
                                std::streamsize           n,
                                milliseconds              timeout,
                                bool&                     t_o)
{
  auto end_time = start + timeout;

  ssize_t n_ret;
  while ((n_ret = ::read(fd, static_cast<void*>(s), static_cast<size_t>(n)))
         < 0) {

    if (errno == EINTR)
      continue; // try read again

    if (errno == ECONNRESET) {
      // LOG(WARNING) << "read(2) raised ECONNRESET, interpreting as EOF";
      return static_cast<std::streamsize>(-1);
    }

    PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN)) << "error from read(2)";

    auto now = system_clock::now();
    if (now < end_time) {
      auto time_left = duration_cast<milliseconds>(end_time - now);
      read_hook();
      if (input_ready(fd, time_left))
        continue; // try read again
    }
    t_o = true;
    LOG(WARNING) << "read(2) timed out";
    return static_cast<std::streamsize>(-1);
  }

  return n_ret;
}

std::streamsize POSIX::write_fd_(time_point<system_clock> start,
                                 int                      fd,
                                 char const*              s,
                                 std::streamsize          n,
                                 milliseconds             timeout,
                                 bool&                    t_o)
{
  auto end_time = start + timeout;

  ssize_t n_ret;
  while (
      (n_ret = ::write(fd, static_cast<const void*>(s), static_cast<size_t>(n)))
      < 0) {

    if (errno == EINTR)
      continue; // try write again

    if (errno == ECONNRESET) {
      // LOG(WARNING) << "write(2) raised ECONNRESET, interpreting as EOF";
      return static_cast<std::streamsize>(-1);
    }

    PCHECK((errno == EWOULDBLOCK) || (errno == EAGAIN))
        << "error from write(2)";

    auto now = system_clock::now();
    if (now < end_time) {
      auto time_left = duration_cast<milliseconds>(end_time - now);
      if (output_ready(fd, time_left))
        continue; // try write again
    }
    t_o = true;
    LOG(WARNING) << "write(2) time out";
    return static_cast<std::streamsize>(-1);
  }

  // The stream buffer code above us can deal with a short read, but
  // not a short write.

  while (n_ret && (n_ret < n)) {
    auto next_n = write_fd_(start, fd, s + n_ret, n - n_ret, timeout, t_o);
    if (next_n == -1)
      break;
    n_ret += next_n;
  }

  return n_ret;
}

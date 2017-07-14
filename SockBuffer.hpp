#ifndef SOCKBUFFER_DOT_HPP
#define SOCKBUFFER_DOT_HPP

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <streambuf>
#include <string>

#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"

#include <glog/logging.h>

// We must define this to account for args to Sockbuffer
#define BOOST_IOSTREAMS_MAX_FORWARDING_ARITY 6

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>

class SockBuffer
    : public boost::iostreams::device<boost::iostreams::bidirectional> {
public:
  SockBuffer& operator=(const SockBuffer&) = delete;
  SockBuffer(SockBuffer const& that)
    : fd_in_(that.fd_in_)
    , fd_out_(that.fd_out_)
    , read_hook_(that.read_hook_)
    , read_timeout_(that.read_timeout_)
    , write_timeout_(that.write_timeout_)
    , starttls_timeout_(that.starttls_timeout_)
    , tls_(that.read_hook_)
  {
    CHECK(!that.timed_out_);
    CHECK(!that.tls_active_);
  }

  SockBuffer(int fd_in,
             int fd_out,
             std::function<void(void)> read_hook,
             std::chrono::milliseconds read_timeout,
             std::chrono::milliseconds write_timeout,
             std::chrono::milliseconds starttls_timeout)
    : fd_in_(fd_in)
    , fd_out_(fd_out)
    , read_hook_(read_hook)
    , read_timeout_(read_timeout)
    , write_timeout_(write_timeout)
    , starttls_timeout_(starttls_timeout)
    , tls_(read_hook_)
  {
    POSIX::set_nonblocking(fd_in_);
    POSIX::set_nonblocking(fd_out_);
  }
  bool input_ready(std::chrono::milliseconds wait) const
  {
    return tls_active_ ? tls_.pending() : POSIX::input_ready(fd_in_, wait);
  }
  bool output_ready(std::chrono::milliseconds wait) const
  {
    return POSIX::output_ready(fd_out_, wait);
  }
  bool timed_out() const { return timed_out_; }
  std::streamsize read(char* s, std::streamsize n)
  {
    return tls_active_ ? tls_.read(s, n, read_timeout_, timed_out_)
                       : POSIX::read(fd_in_, s, n, read_hook_, read_timeout_,
                                     timed_out_);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    return tls_active_
               ? tls_.write(s, n, write_timeout_, timed_out_)
               : POSIX::write(fd_out_, s, n, write_timeout_, timed_out_);
  }
  void starttls_server()
  {
    tls_.starttls_server(fd_in_, fd_out_, starttls_timeout_);
    tls_active_ = true;
  }
  void starttls_client()
  {
    tls_.starttls_client(fd_in_, fd_out_, starttls_timeout_);
    tls_active_ = true;
  }
  std::string tls_info() const
  {
    if (tls_active_) {
      return tls_.info();
    }
    return "";
  }
  bool tls() const { return tls_active_; }

private:
  int fd_in_;
  int fd_out_;

  std::function<void(void)> read_hook_;

  std::chrono::milliseconds read_timeout_;
  std::chrono::milliseconds write_timeout_;
  std::chrono::milliseconds starttls_timeout_;

  bool timed_out_{false};
  bool tls_active_{false};

  TLS tls_;
};

#endif // SOCKBUFFER_DOT_HPP

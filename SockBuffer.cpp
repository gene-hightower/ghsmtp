#include "SockBuffer.hpp"

#include "esc.hpp"

#include <glog/logging.h>

#include <gflags/gflags.h>

DEFINE_bool(log_data, false, "log all protocol data");

SockBuffer::SockBuffer(int fd_in,
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
  log_data_ = (FLAGS_log_data || (getenv("GHSMTP_LOG_DATA") != nullptr));
}

SockBuffer::SockBuffer(SockBuffer const& that)
  : fd_in_(that.fd_in_)
  , fd_out_(that.fd_out_)
  , read_hook_(that.read_hook_)
  , read_timeout_(that.read_timeout_)
  , write_timeout_(that.write_timeout_)
  , starttls_timeout_(that.starttls_timeout_)
  , limit_read_(that.limit_read_)
  , log_data_(that.log_data_)
  , tls_(that.read_hook_)
{
  CHECK(!that.timed_out_);
  CHECK(!that.tls_active_);
  CHECK(!that.limit_read_);
  CHECK(!that.maxed_out());
}

std::streamsize SockBuffer::read(char* s, std::streamsize n)
{
  if (maxed_out()) {
    LOG(ERROR) << "read attempted when"
               << " total of " << octets_read_ << " is over limit of "
               << read_limit_;
    return static_cast<std::streamsize>(-1);
  }
  auto read = tls_active_ ? tls_.read(s, n, read_timeout_, timed_out_)
                          : POSIX::read(fd_in_, s, n, read_hook_, read_timeout_,
                                        timed_out_);
  if (read != static_cast<std::streamsize>(-1)) {
    octets_read_ += read;
    total_octets_read_ += read;
  }
  if (maxed_out()) {
    LOG(ERROR) << "read of " << read << " puts total of " << octets_read_
               << " over limit of " << read_limit_;
    return static_cast<std::streamsize>(-1);
  }

  if (log_data_) {
    auto str = std::string(s, static_cast<size_t>(read));
    LOG(INFO) << "< «" << esc(str, true) << "»";
  }

  return read;
}

std::streamsize SockBuffer::write(const char* s, std::streamsize n)
{
  auto written = tls_active_
                     ? tls_.write(s, n, write_timeout_, timed_out_)
                     : POSIX::write(fd_out_, s, n, write_timeout_, timed_out_);
  if (written != static_cast<std::streamsize>(-1)) {
    octets_written_ += written;
    total_octets_written_ += written;
  }

  if (log_data_) {
    auto str = std::string(s, static_cast<size_t>(written));
    LOG(INFO) << "> «" << esc(str, true) << "»";
  }

  return written;
}

void SockBuffer::log_stats() const
{
  LOG(INFO) << "read_limit_==" << (read_limit_ ? "true" : "false");
  LOG(INFO) << "octets_read_==" << octets_read_;
  LOG(INFO) << "octets_written_==" << octets_written_;
  log_totals();
  if (tls()) {
    LOG(INFO) << tls_info();
  }
}

void SockBuffer::log_totals() const
{
  LOG(INFO) << "total_octets_read_==" << total_octets_read_;
  LOG(INFO) << "total_octets_written_==" << total_octets_written_;
}

#ifndef SOCKBUFFER_DOT_HPP
#define SOCKBUFFER_DOT_HPP

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <streambuf>
#include <string>

#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"

// We must define this to account for args to Sockbuffer ctor.
#define BOOST_IOSTREAMS_MAX_FORWARDING_ARITY 6

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>

namespace Config {
constexpr std::chrono::seconds default_read_timeout{2};
constexpr std::chrono::seconds default_write_timeout{2};
constexpr std::chrono::seconds default_starttls_timeout{2};
} // namespace Config

class SockBuffer
  : public boost::iostreams::device<boost::iostreams::bidirectional> {
public:
  SockBuffer(int fd_in,
             int fd_out,
             std::function<void(void)> read_hook = []() {},
             std::chrono::milliseconds read_timeout
             = Config::default_read_timeout,
             std::chrono::milliseconds write_timeout
             = Config::default_write_timeout,
             std::chrono::milliseconds starttls_timeout
             = Config::default_starttls_timeout);

  SockBuffer& operator=(const SockBuffer&) = delete;
  SockBuffer(SockBuffer const& that);

  bool input_ready(std::chrono::milliseconds wait) const
  {
    return (tls_active_ && tls_.pending()) || POSIX::input_ready(fd_in_, wait);
  }
  bool output_ready(std::chrono::milliseconds wait) const
  {
    return POSIX::output_ready(fd_out_, wait);
  }
  bool maxed_out() const
  {
    return limit_read_ && (octets_read_ >= read_limit_);
  }
  bool timed_out() const { return timed_out_; }

  std::streamsize read(char* s, std::streamsize n);
  std::streamsize write(const char* s, std::streamsize n);

  bool starttls_server()
  {
    return tls_active_
           = tls_.starttls_server(fd_in_, fd_out_, starttls_timeout_);
  }
  bool starttls_client(char const* client_name,
                       char const* server_name,
                       DNS::RR_set const& tlsa_rrs,
                       bool enforce_dane)
  {
    return tls_active_
           = tls_.starttls_client(fd_in_, fd_out_, client_name, server_name,
                                  tlsa_rrs, enforce_dane, starttls_timeout_);
  }
  bool tls() const { return tls_active_; }
  std::string tls_info() const { return tls() ? tls_.info() : ""; }

  void set_max_read(std::streamsize max)
  {
    limit_read_ = true;
    read_limit_ = max;
    octets_read_ = 0;
    octets_written_ = 0;
  }

  void log_stats() const;
  void log_totals() const;

private:
  int fd_in_;
  int fd_out_;

  std::streamsize read_limit_{0};
  std::streamsize octets_read_{0};
  std::streamsize octets_written_{0};
  std::streamsize total_octets_read_{0};
  std::streamsize total_octets_written_{0};

  std::function<void(void)> read_hook_;

  std::chrono::milliseconds read_timeout_;
  std::chrono::milliseconds write_timeout_;
  std::chrono::milliseconds starttls_timeout_;

  bool timed_out_{false};
  bool tls_active_{false};
  bool limit_read_{false};
  bool log_data_{false};

  TLS tls_;
};

#endif // SOCKBUFFER_DOT_HPP

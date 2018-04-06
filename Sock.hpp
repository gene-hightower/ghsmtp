#ifndef SOCK_DOT_HPP
#define SOCK_DOT_HPP

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "SockBuffer.hpp"

namespace Config {
constexpr auto read_timeout_default = std::chrono::seconds(30);
constexpr auto write_timeout_default = std::chrono::seconds(30);
constexpr auto starttls_timeout_default = std::chrono::seconds(30);
} // namespace Config

class Sock {
public:
  Sock(const Sock&) = delete;
  Sock& operator=(const Sock&) = delete;

  Sock(int fd_in,
       int fd_out,
       std::function<void(void)> read_hook = []() {},
       std::chrono::milliseconds read_timeout = Config::read_timeout_default,
       std::chrono::milliseconds write_timeout = Config::write_timeout_default,
       std::chrono::milliseconds starttls_timeout
       = Config::starttls_timeout_default);

  char const* us_c_str() const { return us_addr_str_; }
  char const* them_c_str() const { return them_addr_str_; }
  std::string const& us_address_literal() const { return us_address_literal_; }
  std::string const& them_address_literal() const
  {
    return them_address_literal_;
  }
  bool has_peername() const { return them_addr_str_[0] != '\0'; }
  bool input_ready(std::chrono::milliseconds wait)
  {
    return iostream_->input_ready(wait);
  }
  bool maxed_out() { return iostream_->maxed_out(); }
  bool timed_out() { return iostream_->timed_out(); }

  std::istream& in() { return iostream_; }
  std::ostream& out() { return iostream_; }

  bool starttls_server() { return iostream_->starttls_server(); }
  bool starttls_client(char const* hostname, uint16_t port)
  {
    return iostream_->starttls_client(hostname, port);
  }
  bool tls() { return iostream_->tls(); }
  std::string tls_info() { return iostream_->tls_info(); }

  void set_max_read(std::streamsize max) { iostream_->set_max_read(max); }

  void log_stats() { return iostream_->log_stats(); }
  void log_totals() { return iostream_->log_totals(); }

private:
  boost::iostreams::stream<SockBuffer> iostream_;

  socklen_t us_addr_len_{sizeof us_addr_};
  socklen_t them_addr_len_{sizeof them_addr_};

  union sa {
    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;
    struct sockaddr_storage addr_storage;
  };

  sa us_addr_{};
  sa them_addr_{};

  char us_addr_str_[INET6_ADDRSTRLEN]{'\0'};
  char them_addr_str_[INET6_ADDRSTRLEN]{'\0'};

  std::string us_address_literal_;
  std::string them_address_literal_;
};

#endif // SOCK_DOT_HPP

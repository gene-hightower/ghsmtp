#ifndef SOCK_DOT_HPP
#define SOCK_DOT_HPP

#include <string>

#include "SockBuffer.hpp"
#include "sa.hpp"

namespace Config {
constexpr auto read_timeout_default     = std::chrono::seconds(30);
constexpr auto write_timeout_default    = std::chrono::seconds(30);
constexpr auto starttls_timeout_default = std::chrono::seconds(30);
} // namespace Config

class Sock {
public:
  Sock(const Sock&) = delete;
  Sock& operator=(const Sock&) = delete;

  Sock(int                       fd_in,
       int                       fd_out,
       std::function<void(void)> read_hook     = []() {},
       std::chrono::milliseconds read_timeout  = Config::read_timeout_default,
       std::chrono::milliseconds write_timeout = Config::write_timeout_default,
       std::chrono::milliseconds starttls_timeout
       = Config::starttls_timeout_default);

  char const*        us_c_str() const { return us_addr_str_; }
  char const*        them_c_str() const { return them_addr_str_; }
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

  bool starttls_server(fs::path config_path)
  {
    return iostream_->starttls_server(config_path);
  }
  bool starttls_client(fs::path                  config_path,
                       char const*               client_name,
                       char const*               server_name,
                       DNS::RR_collection const& tlsa_rrs,
                       bool                      enforce_dane)
  {
    return iostream_->starttls_client(config_path, client_name, server_name,
                                      tlsa_rrs, enforce_dane);
  }
  bool        tls() { return iostream_->tls(); }
  std::string tls_info() { return iostream_->tls_info(); }
  bool        verified() { return iostream_->verified(); };

  void set_max_read(std::streamsize max) { iostream_->set_max_read(max); }

  void log_stats() { return iostream_->log_stats(); }
  void log_totals() { return iostream_->log_totals(); }

private:
  boost::iostreams::stream<SockBuffer> iostream_;

  socklen_t us_addr_len_{sizeof us_addr_};
  socklen_t them_addr_len_{sizeof them_addr_};

  sa::sockaddrs us_addr_{};
  sa::sockaddrs them_addr_{};

  char us_addr_str_[INET6_ADDRSTRLEN]{'\0'};
  char them_addr_str_[INET6_ADDRSTRLEN]{'\0'};

  std::string us_address_literal_;
  std::string them_address_literal_;
};

#endif // SOCK_DOT_HPP

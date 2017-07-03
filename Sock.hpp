#ifndef SOCK_DOT_HPP
#define SOCK_DOT_HPP

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "SockBuffer.hpp"

using namespace std::string_literals;

class Sock {
public:
  Sock(const Sock&) = delete;
  Sock& operator=(const Sock&) = delete;

  Sock(int fd_in, int fd_out);

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
  bool timed_out() { return iostream_->timed_out(); }

  std::istream& in() { return iostream_; }
  std::ostream& out() { return iostream_; }

  void starttls() { iostream_->starttls(); }
  bool tls() { return iostream_->tls(); }
  std::string tls_info() { return iostream_->tls_info(); }

private:
  boost::iostreams::stream<SockBuffer> iostream_;

  socklen_t us_addr_len_{sizeof us_addr_};
  socklen_t them_addr_len_{sizeof them_addr_};

  sockaddr_storage us_addr_{0};
  sockaddr_storage them_addr_{0};

  char us_addr_str_[INET6_ADDRSTRLEN]{'\0'};
  char them_addr_str_[INET6_ADDRSTRLEN]{'\0'};

  std::string us_address_literal_;
  std::string them_address_literal_;
};

#endif // SOCK_DOT_HPP

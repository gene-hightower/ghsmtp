#ifndef OPENSSL_DOT_HPP
#define OPENSSL_DOT_HPP

#include <chrono>
#include <functional>
#include <string>

#include <openssl/ssl.h>

#include "stringify.h"

class TLS {
public:
  static constexpr auto cert_path = STRINGIFY(SMTP_HOME) "/smtp.pem";

  TLS& operator=(const TLS&) = delete;

  TLS();
  ~TLS();

  void starttls_client(int fd_in, int fd_out, std::chrono::milliseconds timeout);
  void starttls_server(int fd_in, int fd_out, std::chrono::milliseconds timeout);

  std::streamsize
  read(char* s, std::streamsize n, std::chrono::milliseconds wait, bool& t_o)
  {
    return io_tls_("SSL_read", SSL_read, s, n, wait, t_o);
  }
  std::streamsize write(const char* s,
                        std::streamsize n,
                        std::chrono::milliseconds wait,
                        bool& t_o)
  {
    return io_tls_("SSL_write", SSL_write, const_cast<char*>(s), n, wait, t_o);
  }

  std::string info();

private:
  std::streamsize io_tls_(char const* fnm,
                          std::function<int(SSL*, void*, int)> fnc,
                          char* s,
                          std::streamsize n,
                          std::chrono::milliseconds wait,
                          bool& t_o);

  static void ssl_error() __attribute__((noreturn));

private:
  SSL_CTX* ctx_{nullptr};
  SSL* ssl_{nullptr};
};

#endif // OPENSSL_DOT_HPP

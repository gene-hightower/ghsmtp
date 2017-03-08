#ifndef OPENSSL_DOT_HPP
#define OPENSSL_DOT_HPP

#include <chrono>
#include <functional>
#include <string>

#include <openssl/ssl.h>

class TLS {
public:
  TLS& operator=(const TLS&) = delete;

  TLS();
  ~TLS();

  void starttls(int fd_in, int fd_out, std::chrono::milliseconds timeout);

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

  static void ssl_error();

private:
  SSL_CTX* ctx_{nullptr};
  SSL* ssl_{nullptr};
};

#endif // OPENSSL_DOT_HPP

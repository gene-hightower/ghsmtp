#ifndef OPENSSL_DOT_HPP
#define OPENSSL_DOT_HPP

#include <chrono>
#include <functional>
#include <string>

#include <openssl/ssl.h>

class TLS {
public:
  static constexpr auto cert_fn = "smtp.pem";
  static constexpr auto key_fn = "smtp.key";

  TLS(TLS const&) = delete;
  TLS& operator=(const TLS&) = delete;

  TLS(std::function<void(void)> read_hook);
  ~TLS();

  void
  starttls_client(int fd_in, int fd_out, std::chrono::milliseconds timeout);
  void
  starttls_server(int fd_in, int fd_out, std::chrono::milliseconds timeout);

  bool pending() const { return SSL_pending(ssl_) > 0; }

  std::streamsize
  read(char* s, std::streamsize n, std::chrono::milliseconds wait, bool& t_o)
  {
    return io_tls_("SSL_read", SSL_read, s, n, wait, t_o);
  }
  std::streamsize write(const char* c_s,
                        std::streamsize n,
                        std::chrono::milliseconds wait,
                        bool& t_o)
  {
    auto s = const_cast<char*>(c_s);
    return io_tls_("SSL_write", SSL_write, s, n, wait, t_o);
  }

  std::string info() const;

private:
  std::streamsize io_tls_(char const* fnm,
                          std::function<int(SSL*, void*, int)> io_fnc,
                          char* s,
                          std::streamsize n,
                          std::chrono::milliseconds wait,
                          bool& t_o);

  static void ssl_error() __attribute__((noreturn));

private:
  SSL_CTX* ctx_{nullptr};
  SSL* ssl_{nullptr};
  std::function<void(void)> read_hook_;
  bool verified_{false};
};

#endif // OPENSSL_DOT_HPP

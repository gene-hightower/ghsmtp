#ifndef TLS_OPENSSL_DOT_HPP
#define TLS_OPENSSL_DOT_HPP

#include "Domain.hpp"

#include <chrono>
#include <functional>

#include <openssl/ssl.h>

namespace Config {
auto constexpr cert_verify_depth{10};

auto constexpr cert_fn = "smtp.pem";
auto constexpr key_fn = "smtp.key";
auto constexpr cert_fn_re = ".+\\.pem$";

} // namespace Config

class TLS {
public:
  TLS(TLS const&) = delete;
  TLS& operator=(const TLS&) = delete;

  explicit TLS(std::function<void(void)> read_hook);
  ~TLS();

  bool starttls_client(int fd_in,
                       int fd_out,
                       char const* hostname,
                       uint16_t port,
                       std::chrono::milliseconds timeout);
  bool
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

  struct per_cert_ctx {
    explicit per_cert_ctx(SSL_CTX* ctx_, std::vector<Domain> cn_)
      : ctx(ctx_)
      , cn(cn_)
    {
    }

    SSL_CTX* ctx;
    std::vector<Domain> cn;
  };

private:
  std::streamsize io_tls_(char const* fnm,
                          std::function<int(SSL*, void*, int)> io_fnc,
                          char* s,
                          std::streamsize n,
                          std::chrono::milliseconds wait,
                          bool& t_o);

  static void ssl_error();

private:
  SSL* ssl_{nullptr};

  std::vector<per_cert_ctx> cert_ctx_;

  std::function<void(void)> read_hook_;

  bool verified_{false};
};

#endif // TLS_OPENSSL_DOT_HPP

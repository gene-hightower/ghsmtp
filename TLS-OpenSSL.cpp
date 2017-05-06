#include <chrono>
#include <functional>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <openssl/rand.h>

#include <openssl/opensslv.h>

#include <glog/logging.h>

#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"

TLS::TLS() {}

TLS::~TLS()
{
  if (ssl_) {
    SSL_free(ssl_);
  }
  if (ctx_) {
    SSL_CTX_free(ctx_);
  }
}

void TLS::starttls(int fd_in, int fd_out, std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
#else
  OPENSSL_init_ssl(0, nullptr);
#endif

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.
  OpenSSL_add_all_algorithms();

  const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_server_method());
  ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

  CHECK(SSL_CTX_use_certificate_file(ctx_, cert_path, SSL_FILETYPE_PEM) > 0)
      << "Can't load certificate file \"" << cert_path << "\"";
  CHECK(SSL_CTX_use_PrivateKey_file(ctx_, cert_path, SSL_FILETYPE_PEM) > 0)
      << "Can't load private key file \"" << cert_path << "\"";

  CHECK(SSL_CTX_check_private_key(ctx_))
      << "Private key does not match the public certificate";

  // RFC 3526
  constexpr char g_dh4096_sz[]
      = "-----BEGIN DH PARAMETERS-----\n"
        "MIICCAKCAgEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n"
        "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\n"
        "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n"
        "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n"
        "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n"
        "5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYM\n"
        "fbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshq\n"
        "ZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEI\n"
        "ARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O\n"
        "+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBI\n"
        "HNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0BjGZ//////////8CAQI=\n"
        "-----END DH PARAMETERS-----";

  BIO* bio = CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(g_dh4096_sz), -1));
  DH* dh = CHECK_NOTNULL(PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

  SSL_CTX_set_tmp_dh(ctx_, dh);

#pragma GCC diagnostic pop

  DH_free(dh);
  BIO_free(bio);

  // CHECK_EQ(1, SSL_CTX_set_cipher_list(ctx_, "!SSLv2:SSLv3:TLSv1"));

  ssl_ = CHECK_NOTNULL(SSL_new(ctx_));
  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  int rc;
  while ((rc = SSL_accept(ssl_)) < 0) {

    time_point<system_clock> now = system_clock::now();

    CHECK(now < (start + timeout)) << "starttls timed out";

    milliseconds time_left
        = duration_cast<milliseconds>((start + timeout) - now);

    switch (SSL_get_error(ssl_, rc)) {
    case SSL_ERROR_WANT_READ:
      CHECK(POSIX::input_ready(fd_in, time_left))
          << "starttls timed out on input_ready";
      continue; // try SSL_accept again

    case SSL_ERROR_WANT_WRITE:
      CHECK(POSIX::output_ready(fd_out, time_left))
          << "starttls timed out on output_ready";
      continue; // try SSL_accept again

    default:
      ssl_error();
    }
  }
}

std::string TLS::info()
{
  std::ostringstream info;

  SSL_CIPHER const* const c = SSL_get_current_cipher(ssl_);
  if (c) {
    info << "version=" << SSL_CIPHER_get_version(c);
    info << " cipher=" << SSL_CIPHER_get_name(c);
    int alg_bits;
    int bits = SSL_CIPHER_get_bits(c, &alg_bits);
    info << " bits=" << bits << "/" << alg_bits;
  }

  return info.str();
}

std::streamsize TLS::io_tls_(char const* fnm,
                             std::function<int(SSL*, void*, int)> fnc,
                             char* s,
                             std::streamsize n,
                             std::chrono::milliseconds wait,
                             bool& t_o)
{
  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  int n_ret;
  while ((n_ret = fnc(ssl_, static_cast<void*>(s), static_cast<int>(n))) < 0) {
    time_point<system_clock> now = system_clock::now();
    if (now > (start + wait)) {
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    milliseconds time_left = duration_cast<milliseconds>((start + wait) - now);

    switch (SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_WANT_READ: {
      int fd = SSL_get_rfd(ssl_);
      CHECK_NE(-1, fd);
      if (POSIX::input_ready(fd, time_left))
        continue; // try fnc again
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    case SSL_ERROR_WANT_WRITE: {
      int fd = SSL_get_wfd(ssl_);
      CHECK_NE(-1, fd);
      if (POSIX::output_ready(fd, time_left))
        continue; // try fnc again
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    default:
      ssl_error();
    }
  }

  // The strange (and never before seen) case of 0 return.
  if (0 == n_ret) {
    switch (SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_NONE:
      LOG(INFO) << fnm << " returned SSL_ERROR_NONE";
      break;

    case SSL_ERROR_ZERO_RETURN:
      // This is a close, not at all sure this is the right thing to do.
      LOG(FATAL) << fnm << " returned SSL_ERROR_ZERO_RETURN";

    default:
      LOG(INFO) << fnm << " returned zero";
      ssl_error();
    }
  }

  return static_cast<std::streamsize>(n_ret);
}

void TLS::ssl_error()
{
  unsigned long er;
  while (0 != (er = ERR_get_error()))
    LOG(ERROR) << ERR_error_string(er, nullptr);
  LOG(FATAL) << "fatal OpenSSL error";
}

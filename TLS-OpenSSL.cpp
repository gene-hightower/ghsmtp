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

TLS::TLS(std::function<void(void)> read_hook)
  : read_hook_(read_hook)
{
}

TLS::~TLS()
{
  if (ssl_) {
    SSL_free(ssl_);
  }
  if (ctx_) {
    SSL_CTX_free(ctx_);
  }
}

void TLS::starttls_client(int fd_in,
                          int fd_out,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_client_method());
  ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

  constexpr long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
  SSL_CTX_set_options(ctx_, flags);

  ssl_ = CHECK_NOTNULL(SSL_new(ctx_));
  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  int rc;
  while ((rc = SSL_connect(ssl_)) < 0) {

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

void TLS::starttls_server(int fd_in,
                          int fd_out,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_server_method());
  ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

  constexpr long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
  SSL_CTX_set_options(ctx_, flags);

  // <https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/37376.pdf>

  // Shooting for ECDHE-RSA-AES128-GCM-SHA256, since OpenSSL will pick
  // the larger AES given the option, we remove them.

  // // clang-format off
  // char const* cipher_list
  //     = "ECDHE-RSA-AES128-GCM-SHA256:"
  //       "ECDHE-ECDSA-AES128-GCM-SHA256:"
  //       // "ECDHE-RSA-AES256-GCM-SHA384:"
  //       // "ECDHE-ECDSA-AES256-GCM-SHA384:"
  //       "DHE-RSA-AES128-GCM-SHA256:"
  //       "kEDH+AESGCM:"
  //       "ECDHE-RSA-AES128-SHA256:"
  //       "ECDHE-ECDSA-AES128-SHA256:"
  //       "ECDHE-RSA-AES128-SHA:"
  //       "ECDHE-ECDSA-AES128-SHA:"
  //       // "ECDHE-RSA-AES256-SHA384:"
  //       // "ECDHE-ECDSA-AES256-SHA384:"
  //       // "ECDHE-RSA-AES256-SHA:"
  //       // "ECDHE-ECDSA-AES256-SHA:"
  //       "DHE-RSA-AES128-SHA256:"
  //       "DHE-RSA-AES128-SHA:"
  //       // "DHE-RSA-AES256-SHA256:"
  //       // "DHE-RSA-AES256-SHA:"
  //       "!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK";
  // // clang-format on

  // CHECK(SSL_CTX_set_cipher_list(ctx_, cipher_list) > 0)
  //     << "Can't set cipher list to " << cipher_list;

  CHECK(SSL_CTX_use_certificate_file(ctx_, cert_path, SSL_FILETYPE_PEM) > 0)
      << "Can't load certificate file \"" << cert_path << "\"";
  CHECK(SSL_CTX_use_PrivateKey_file(ctx_, cert_path, SSL_FILETYPE_PEM) > 0)
      << "Can't load private key file \"" << cert_path << "\"";

  CHECK(SSL_CTX_check_private_key(ctx_))
      << "Private key does not match the public certificate";

  // <https://wiki.mozilla.org/Security/Server_Side_TLS#DHE_handshake_and_dhparam>
  constexpr char ffdhe4096[] = R"(
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----
)";

  BIO* bio = CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(ffdhe4096), -1));
  DH* dh = CHECK_NOTNULL(PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr));

  auto ecdh = CHECK_NOTNULL(EC_KEY_new_by_curve_name(NID_secp521r1));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

  SSL_CTX_set_tmp_dh(ctx_, dh);
  SSL_CTX_set_tmp_ecdh(ctx_, ecdh);

#pragma GCC diagnostic pop

  DH_free(dh);
  BIO_free(bio);

  EC_KEY_free(ecdh);

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

    switch (auto err = SSL_get_error(ssl_, rc)) {
    case SSL_ERROR_WANT_READ:
      CHECK(POSIX::input_ready(fd_in, time_left))
          << "starttls timed out on input_ready";
      continue; // try SSL_accept again

    case SSL_ERROR_WANT_WRITE:
      CHECK(POSIX::output_ready(fd_out, time_left))
          << "starttls timed out on output_ready";
      continue; // try SSL_accept again

    default:
      LOG(ERROR) << "err == " << err;
      ssl_error();
    }
  }
}

std::string TLS::info() const
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
                             std::function<int(SSL*, void*, int)> io_fnc,
                             char* s,
                             std::streamsize n,
                             std::chrono::milliseconds wait,
                             bool& t_o)
{
  using namespace std::chrono;
  time_point<system_clock> start = system_clock::now();

  int n_ret;
  while ((n_ret = io_fnc(ssl_, static_cast<void*>(s), static_cast<int>(n)))
         < 0) {
    time_point<system_clock> now = system_clock::now();
    if (now > (start + wait)) {
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    milliseconds time_left = duration_cast<milliseconds>((start + wait) - now);

    switch (auto err = SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_WANT_READ: {
      int fd = SSL_get_rfd(ssl_);
      CHECK_NE(-1, fd);
      read_hook_();
      if (POSIX::input_ready(fd, time_left))
        continue; // try io_fnc again
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    case SSL_ERROR_WANT_WRITE: {
      int fd = SSL_get_wfd(ssl_);
      CHECK_NE(-1, fd);
      if (POSIX::output_ready(fd, time_left))
        continue; // try io_fnc again
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    default:
      LOG(ERROR) << "err == " << err;
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

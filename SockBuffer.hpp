/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SOCKBUFFER_DOT_HPP
#define SOCKBUFFER_DOT_HPP

#include <cerrno>
#include <chrono>
#include <cstring> // std::strerror
#include <functional>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>

#include <fcntl.h>
#include <sys/select.h>

#include "Logging.hpp"

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace Config {
// Read timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout = std::chrono::minutes(5);
constexpr auto write_timeout = std::chrono::seconds(10);
constexpr auto starttls_timeout = std::chrono::seconds(10);
}

class runtime_error_from_errno : public std::runtime_error {
public:
  explicit runtime_error_from_errno(int e)
    : std::runtime_error(errno_to_string(e))
  {
  }

private:
  static std::string errno_to_string(int e)
  {
    std::stringstream ss;
    ss << "read() error errno==" << e << ": " << std::strerror(e);
    return ss.str();
  }
};

class SockBuffer
    : public boost::iostreams::device<boost::iostreams::bidirectional> {
public:
  SockBuffer& operator=(const SockBuffer&) = delete;
  SockBuffer(const SockBuffer& that)
    : fd_in_(that.fd_in_)
    , fd_out_(that.fd_out_)
    , timed_out_(false)
    , tls_(false)
    , ctx_(that.ctx_)
    , ssl_(that.ssl_)
  {
    that.ctx_ = nullptr;
    that.ssl_ = nullptr;
  }
  SockBuffer(int fd_in, int fd_out)
    : fd_in_(fd_in)
    , fd_out_(fd_out)
    , timed_out_(false)
    , tls_(false)
    , ctx_(nullptr)
    , ssl_(nullptr)
  {
    int flags;
    PCHECK((flags = fcntl(fd_in_, F_GETFL, 0)) != -1);
    if (0 == (flags & O_NONBLOCK)) {
      PCHECK(fcntl(fd_in_, F_SETFL, flags | O_NONBLOCK) != -1);
    }
    PCHECK((flags = fcntl(fd_out_, F_GETFL, 0)) != -1);
    if (0 == (flags & O_NONBLOCK)) {
      PCHECK(fcntl(fd_out_, F_SETFL, flags | O_NONBLOCK) != -1);
    }

    // TLS

    SSL_load_error_strings();
    SSL_library_init();
    CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_server_method());
    ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

    if (SSL_CTX_use_certificate_file(ctx_, "/z/home/gene/src/smtpd/cert.pem",
                                     SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, "/z/home/gene/src/smtpd/cert.pem",
                                    SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    CHECK(SSL_CTX_check_private_key(ctx_))
        << "Private key does not match the public certificate";

    constexpr char dh_ike_23_pem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIICCgKCAQEArRB+HpEjqdDWYPqnlVnFH6INZOVoO5/RtUsVl7YdCnXm+hQd+VpW\n"
        "26+aPEB7od8V6z1oijCcGA4d5rhaEnSgpm0/gVKtasISkDfJ7e/aTfjZHo/vVbc5\n"
        "S3rVt9C2wSIHyfmNEe002/bGugssi7wnvmoA4KC5xJcIs7+KMXCRiDaBKGEwvImF\n"
        "2xYC5xRBXZMwJ4Jzx94x79xzEPcSH9WgdBWYfZrcCkhtzfk6zEQyg4cxXXXhmMZB\n"
        "pIDNhqG55YfovmDmnMkosrnFIXLkEwQumyPxCw4W55djybU9z0uoCinj+3PBa451\n"
        "uX7zY+L/ox9xz53lOE5xuBwKxN/+DBDmTwKCAQEArEAy708tmuOd8wtcj/2sUGze\n"
        "vnuJmYyvdIZqCM/k/+OmgkpOELmm8N2SHwGnDEr6q3OddwDCn1LFfbF8YgqGUr5e\n"
        "kAGo1mrXwXZpEBmZAkr00CcnWsE0i7inYtBSG8mK4kcVBCLqHtQJk51U2nRgzbX2\n"
        "xrJQcXy+8YDrNBGOmNEZUppF1vg0Vm4wJeMWozDvu3eobwwasVsFGuPUKMj4rLcK\n"
        "gTcVC47rEOGD7dGZY93Z4mPkdwWJ72qiHn9fL/OBtTnM40CdE81Wavu0jWwBkYHh\n"
        "vP6UswJp7f5y/ptqpL17Wg8ccc//TBnEGOH27AF5gbwIfypwZbOEuJDTGR8r+g==\n"
        "-----END DH PARAMETERS-----\n";

    BIO* bio =
        CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(dh_ike_23_pem), -1));
    DH* dh =
        CHECK_NOTNULL(PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

    SSL_CTX_set_tmp_dh(ctx_, dh);

#pragma GCC diagnostic pop

    DH_free(dh);
    BIO_free(bio);

#ifdef NEED_RSA_CALLBACK
    SSL_CTX_set_tmp_rsa_callback(ctx_, rsa_callback);
#endif

    // SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);

    // CHECK_EQ(1, SSL_CTX_set_cipher_list(ctx_, "!SSLv2:SSLv3:TLSv1"));
  }
  ~SockBuffer()
  {
    if (ctx_) {
      EVP_cleanup();
      SSL_CTX_free(ctx_);
    }
    if (ssl_) {
      SSL_free(ssl_);
    }
  }
  bool input_ready(std::chrono::milliseconds wait) const
  {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd_in_, &fds);

    struct timeval tv;
    tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
    tv.tv_usec = (wait.count() % 1000) * 1000;

    int puts;
    PCHECK((puts = select(fd_in_ + 1, &fds, nullptr, nullptr, &tv)) != -1);

    return 0 != puts;
  }
  bool output_ready(std::chrono::milliseconds wait) const
  {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd_out_, &fds);

    struct timeval tv;
    tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
    tv.tv_usec = (wait.count() % 1000) * 1000;

    int puts;
    PCHECK((puts = select(fd_out_ + 1, nullptr, &fds, nullptr, &tv)) != -1);

    return 0 != puts;
  }
  bool timed_out() const
  {
    return timed_out_;
  }
  std::streamsize read(char* s, std::streamsize n)
  {
    return tls_ ? read_tls(s, n) : read_fd(s, n);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    return tls_ ? write_tls(s, n) : write_fd(s, n);
  }
  void starttls()
  {
    ssl_ = CHECK_NOTNULL(SSL_new(ctx_));
    SSL_set_rfd(ssl_, fd_in_);
    SSL_set_wfd(ssl_, fd_out_);

    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    int rc;
    while ((rc = SSL_accept(ssl_)) < 0) {

      time_point<system_clock> now = system_clock::now();

      CHECK(now < (start + Config::starttls_timeout)) << "starttls timed out";

      milliseconds time_left =
          duration_cast<milliseconds>((start + Config::starttls_timeout) - now);

      switch (SSL_get_error(ssl_, rc)) {
      case SSL_ERROR_WANT_READ:
        CHECK(input_ready(time_left)) << "starttls timed out on input_ready";
        continue; // try SSL_accept again

      case SSL_ERROR_WANT_WRITE:
        CHECK(output_ready(time_left)) << "starttls timed out on output_ready";
        continue; // try SSL_accept again

      default:
        ssl_error();
      }
    }

    tls_ = true;
  }
  std::string tls_info()
  {
    std::ostringstream info;
    if (tls_) {
      SSL_CIPHER const* const c = SSL_get_current_cipher(ssl_);
      if (c) {
        info << "version=" << SSL_CIPHER_get_version(c);
        info << " cipher=" << SSL_CIPHER_get_name(c);
        int alg_bits;
        int bits = SSL_CIPHER_get_bits(c, &alg_bits);
        info << " bits=" << bits << "/" << alg_bits;
      }
    }
    return info.str();
  }
  bool tls()
  {
    return tls_;
  }

private:
  std::streamsize io_fd(char const* fnm,
                        std::function<ssize_t(int, void*, size_t)> fnc,
                        int fd,
                        std::chrono::milliseconds timeout, char* s,
                        std::streamsize n)
  {
    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    ssize_t n_ret;
    while ((n_ret = fnc(fd, static_cast<void*>(s),
                        static_cast<size_t>(n))) < 0) {

      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
        time_point<system_clock> now = system_clock::now();
        if (now < (start + timeout)) {
          milliseconds time_left =
              duration_cast<milliseconds>((start + timeout) - now);
          if (input_ready(time_left))
            continue; // try fnc again
        }
        timed_out_ = true;
        LOG(WARNING) << fnm << " timed out";
        return static_cast<std::streamsize>(-1);
      }

      if (errno == EINTR)
        continue; // try fnc again

      throw runtime_error_from_errno(errno);
    }

    if (0 == n_ret) {
      LOG(WARNING) << fnm << " returned zero, interpreting as EOF";
      return static_cast<std::streamsize>(-1);
    }

    return static_cast<std::streamsize>(n_ret);
  }
  std::streamsize read_fd(char* s, std::streamsize n)
  {
    return io_fd("read", ::read, fd_in_, Config::read_timeout, s, n);
  }
  std::streamsize write_fd(const char* s, std::streamsize n)
  {
    return io_fd("write", ::write, fd_out_, Config::write_timeout, const_cast<char*>(s),
                 n);
  }

  std::streamsize io_tls(char const* fnm,
                         std::function<int(SSL*, void*, int)> fnc,
                         std::chrono::milliseconds timeout, char* s,
                         std::streamsize n)
  {
    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    int n_ret;
    while ((n_ret = fnc(ssl_, static_cast<void*>(s), static_cast<int>(n))) <
           0) {
      time_point<system_clock> now = system_clock::now();
      if (now > (start + timeout)) {
        LOG(WARNING) << fnm << " timed out";
        timed_out_ = true;
        return static_cast<std::streamsize>(-1);
      }

      milliseconds time_left =
          duration_cast<milliseconds>((start + timeout) - now);

      switch (SSL_get_error(ssl_, n_ret)) {
      case SSL_ERROR_WANT_READ:
        if (input_ready(time_left))
          continue; // try fnc again
        LOG(WARNING) << fnm << " timed out";
        timed_out_ = true;
        return static_cast<std::streamsize>(-1);

      case SSL_ERROR_WANT_WRITE:
        if (output_ready(time_left))
          continue; // try fnc again
        LOG(WARNING) << fnm << " timed out";
        timed_out_ = true;
        return static_cast<std::streamsize>(-1);

      default:
        ssl_error();
      }
    }

    // The strange case of 0 return.
    if (0 == n_ret) {
      switch (SSL_get_error(ssl_, n_ret)) {
      case SSL_ERROR_NONE:
        LOG(INFO) << fnm << " returned SSL_ERROR_NONE";
        break;

      case SSL_ERROR_ZERO_RETURN:
        // This is a close, not at all sure this is the right thing to do.
        LOG(INFO) << fnm << " returned SSL_ERROR_ZERO_RETURN";
        tls_ = false;
        break;

      default:
        LOG(INFO) << fnm << " returned zero";
        ssl_error();
      }
    }

    return static_cast<std::streamsize>(n_ret);
  }
  std::streamsize read_tls(char* s, std::streamsize n)
  {
    return io_tls("SSL_read", SSL_read, Config::read_timeout, s, n);
  }
  std::streamsize write_tls(const char* s, std::streamsize n)
  {
    return io_tls("SSL_write", SSL_write, Config::write_timeout,
                  const_cast<char*>(s), n);
  }

  static void ssl_error()
  {
    unsigned long er;
    LOG(ERROR) << "SSL error";
    while (0 != (er = ERR_get_error()))
      LOG(ERROR) << ERR_error_string(er, nullptr);
    abort();
  }

#ifdef NEED_RSA_CALLBACK
  static RSA* rsa_callback(SSL* s, int ex, int keylength)
  {
    LOG(INFO) << "generating " << keylength << " bit RSA key";

    RSA* rsa_key = RSA_generate_key(keylength, RSA_F4, nullptr, nullptr);
    if (rsa_key == NULL) {
      static char ssl_errstring[256];
      ERR_error_string(ERR_get_error(), ssl_errstring);
      LOG(ERROR) << "TLS error (RSA_generate_key): " << ssl_errstring;
      return NULL;
    }
    return rsa_key;
  }
#endif

private:
  int fd_in_;
  int fd_out_;

  bool timed_out_;

  bool tls_;
  mutable SSL_CTX* ctx_;
  mutable SSL* ssl_;
};

#endif // SOCKBUFFER_DOT_HPP

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
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace Config {
// Timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout = std::chrono::minutes(5);
constexpr auto write_timeout = std::chrono::seconds(5);
constexpr auto starttls_timeout = std::chrono::seconds(5);
}

class io_error : public std::runtime_error {
public:
  explicit io_error(int e) : std::runtime_error(errno_to_str(e))
  {
  }

private:
  static std::string errno_to_str(int e)
  {
    std::stringstream ss;
    ss << "read() error errno==" << e << ": " << std::strerror(e);
    return ss.str();
  }
};

class SockBuffer
    : public boost::iostreams::device<boost::iostreams::bidirectional> {
public:
  SockBuffer(int fd_in, int fd_out)
    : fd_in_(fd_in)
    , fd_out_(fd_out)
    , timed_out_(false)
    , tls_(false)
  {
    int flags;
    PCHECK((flags = fcntl(fd_in_, F_GETFL, 0)) != -1);
    PCHECK(fcntl(fd_in_, F_SETFL, flags | O_NONBLOCK) != -1);

    // TLS

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_server_method());
    ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

    CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

    if (SSL_CTX_use_certificate_file(ctx_, "/home/gene/src/smtpd/cert.pem",
                                     SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, "/home/gene/src/smtpd/cert.pem",
                                    SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    CHECK(SSL_CTX_check_private_key(ctx_))
        << "Private key does not match the public certificate";
  }
  ~SockBuffer()
  {
    // ??
    // SSL_CTX_free(ctx_);
  }
  bool input_ready(std::chrono::milliseconds wait) const
  {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd_in_, &rfds);

    struct timeval tv;
    tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
    tv.tv_usec = (wait.count() % 1000) * 1000;

    int inputs;
    PCHECK((inputs = select(fd_in_ + 1, &rfds, nullptr, nullptr, &tv)) != -1);

    return 0 != inputs;
  }
  bool output_ready(std::chrono::milliseconds wait) const
  {
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd_out_, &wfds);

    struct timeval tv;
    tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(wait).count();
    tv.tv_usec = (wait.count() % 1000) * 1000;

    int inputs;
    PCHECK((inputs = select(fd_out_ + 1, nullptr, &wfds, nullptr, &tv)) != -1);

    return 0 != inputs;
  }
  bool timed_out() const
  {
    return timed_out_;
  }
  std::streamsize read(char* s, std::streamsize n)
  {
    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    if (tls_) {
      int ssl_n_read;
      while ((ssl_n_read = SSL_read(ssl_, static_cast<void*>(s),
                                    static_cast<int>(n))) < 0) {
        time_point<system_clock> now = system_clock::now();
        if (now > (start + Config::read_timeout)) {
          LOG(ERROR) << "SSL_read timed out";
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);
        }

        milliseconds t_o =
            duration_cast<milliseconds>((start + Config::read_timeout) - now);

        switch (SSL_get_error(ssl_, ssl_n_read)) {
        case SSL_ERROR_WANT_READ:
          if (input_ready(t_o))
            continue;
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);

        case SSL_ERROR_WANT_WRITE:
          if (output_ready(t_o))
            continue;
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
          ssl_error();
        }
      }

      if (ssl_n_read == 0) {
        // This is a close
        tls_ = false;
      }

      return static_cast<std::streamsize>(ssl_n_read);
    }

    ssize_t n_read;
    while ((n_read = ::read(fd_in_, static_cast<void*>(s),
                            static_cast<size_t>(n))) < 0) {

      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {

        time_point<system_clock> now = system_clock::now();
        if (now < (start + Config::read_timeout))
          if (input_ready(duration_cast<milliseconds>(
                  (start + Config::read_timeout) - now)))
            continue;

        timed_out_ = true;
        return static_cast<std::streamsize>(-1);
      }

      if (errno == EINTR)
        continue;

      throw io_error(errno);
    }

    if (0 == n_read)
      return static_cast<std::streamsize>(-1);

    return static_cast<std::streamsize>(n_read);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    if (tls_) {
      int ssl_n_write;
      while ((ssl_n_write = SSL_write(ssl_, static_cast<const void*>(s),
                                      static_cast<size_t>(n))) < 0) {
        time_point<system_clock> now = system_clock::now();
        if (now > (start + Config::write_timeout)) {
          LOG(ERROR) << "SSL_write timed out";
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);
        }

        milliseconds t_o =
            duration_cast<milliseconds>((start + Config::write_timeout) - now);

        switch (SSL_get_error(ssl_, ssl_n_write)) {
        case SSL_ERROR_WANT_READ:
          if (input_ready(t_o))
            continue;
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);

        case SSL_ERROR_WANT_WRITE:
          if (output_ready(t_o))
            continue;
          timed_out_ = true;
          return static_cast<std::streamsize>(-1);

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
          ssl_error();
        }
      }
      if (0 == ssl_n_write) {
        // This is a close
        tls_ = false;
      }
    }

    ssize_t n_write;
    while ((n_write = ::write(fd_out_, static_cast<const void*>(s),
                              static_cast<size_t>(n))) < 0) {
      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {

        time_point<system_clock> now = system_clock::now();
        if (now < (start + Config::write_timeout))
          if (output_ready(duration_cast<milliseconds>(
                  (start + Config::write_timeout) - now)))
            continue;

        timed_out_ = true;
        return static_cast<std::streamsize>(-1);
      }

      if (errno == EINTR)
        continue;

      throw io_error(errno);
    }

    if (0 == n_write)
      return static_cast<std::streamsize>(-1);

    return static_cast<std::streamsize>(n_write);
  }
  void starttls()
  {
    ssl_ = SSL_new(ctx_);
    if (!ssl_) {
      ssl_error();
    }
    if (!SSL_set_rfd(ssl_, fd_in_)) {
      ssl_error();
    }
    if (!SSL_set_wfd(ssl_, fd_out_)) {
      ssl_error();
    }

    using namespace std::chrono;
    time_point<system_clock> start = system_clock::now();

    int rc;
    while ((rc = SSL_accept(ssl_)) < 0) {

      time_point<system_clock> now = system_clock::now();
      if (now > (start + Config::starttls_timeout)) {
        LOG(ERROR) << "starttls timed out";
        return;
      }

      milliseconds t_o =
          duration_cast<milliseconds>((start + Config::starttls_timeout) - now);

      switch (SSL_get_error(ssl_, rc)) {
      case SSL_ERROR_WANT_READ:
        if (input_ready(t_o))
          continue;
        LOG(ERROR) << "starttls timed out on input_ready";
        return;

      case SSL_ERROR_WANT_WRITE:
        if (output_ready(t_o))
          continue;
        LOG(ERROR) << "starttls timed out on output_ready";
        continue;

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

private:
  void ssl_error()
  {
    unsigned long er;
    LOG(ERROR) << "SSL error";
    while (0 != (er = ERR_get_error()))
      LOG(ERROR) << ERR_error_string(er, nullptr);
    abort();
  }

private:
  int fd_in_;
  int fd_out_;

  bool timed_out_;

  bool tls_;
  SSL_CTX* ctx_;
  SSL* ssl_;
};

#endif // SOCKBUFFER_DOT_HPP

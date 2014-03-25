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

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace Config {
// Timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout = std::chrono::minutes(5);
}

class read_error : public std::runtime_error {
public:
  explicit read_error(int e) : std::runtime_error(errno_to_str(e))
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
  explicit SockBuffer(int fd_in, int fd_out)
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

    const SSL_METHOD* method = CHECK_NOTNULL(SSLv2_server_method());
    ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

    if (SSL_CTX_use_certificate_file(ctx_, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
      ssl_error();
    }
    CHECK(SSL_CTX_check_private_key(ctx_))
        << "Private key does not match the public certificate";
  }
  ~SockBuffer()
  {
    SSL_CTX_free(ctx_);
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
    std::chrono::time_point<std::chrono::system_clock> start =
        std::chrono::system_clock::now();

    if (tls_) {
      int ssl_n_read;
      while ((ssl_n_read = SSL_read(ssl_, static_cast<void*>(s),
                                    static_cast<int>(n))) < 0) {
        std::chrono::time_point<std::chrono::system_clock> now =
            std::chrono::system_clock::now();

        switch (SSL_get_error(ssl_, ssl_n_read)) {
        case SSL_ERROR_WANT_READ:
          if (now < (start + Config::read_timeout))
            if (input_ready(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        (start + Config::read_timeout) - now)))
              continue;

          timed_out_ = true;
          return static_cast<std::streamsize>(-1);

        case SSL_ERROR_WANT_WRITE:
          if (now < (start + Config::read_timeout))
            if (output_ready(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        (start + Config::read_timeout) - now)))
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
        // XXX
        // This is a close
      }

      return static_cast<std::streamsize>(ssl_n_read);
    }

    ssize_t n_read;
    while ((n_read = ::read(fd_in_, static_cast<void*>(s),
                            static_cast<size_t>(n))) < 0) {

      if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {

        std::chrono::time_point<std::chrono::system_clock> now =
            std::chrono::system_clock::now();

        if (now < (start + Config::read_timeout))
          if (input_ready(std::chrono::duration_cast<std::chrono::milliseconds>(
                  (start + Config::read_timeout) - now)))
            continue;

        timed_out_ = true;
        return static_cast<std::streamsize>(-1);
      }

      if (errno == EINTR)
        continue;

      throw read_error(errno);
    }

    if (0 == n_read)
      return static_cast<std::streamsize>(-1);

    return static_cast<std::streamsize>(n_read);
  }
  std::streamsize write(const char* s, std::streamsize n)
  {
    if (tls_) {
      return SSL_write(ssl_, static_cast<const void*>(s),
                       static_cast<size_t>(n));
    }

    return ::write(fd_out_, static_cast<const void*>(s),
                   static_cast<size_t>(n));
  }
  void starttls()
  {
    ssl_ = SSL_new(ctx_);
    if (!ssl_) {
      ssl_error();
    }
    if (!SSL_set_fd(ssl_, fd_in_)) {
      ssl_error();
    }
    if (-1 == SSL_accept(ssl_)) { // Negotiate the TLS connection.
      ssl_error();
    }

    X509* cert = SSL_get_peer_certificate(ssl_);
    if (cert) {
      // OpenSSL functions should never throw...
      std::unique_ptr<char> subject(
          X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0));
      std::unique_ptr<char> issuer(
          X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0));
      X509_free(cert);

      LOG(INFO) << "Subject: " << subject.get();
      LOG(INFO) << "Issuer: " << issuer.get();
    }

    tls_ = true;
  }

private:
  void ssl_error()
  {
    unsigned long er;
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

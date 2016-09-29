/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

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

#include <chrono>
#include <functional>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <openssl/rand.h>

#include <glog/logging.h>

#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"

#include "stringify.h"

TLS::TLS()
{
  SSL_load_error_strings();
  SSL_library_init();
  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.
  OpenSSL_add_all_algorithms();

  const SSL_METHOD* method = CHECK_NOTNULL(SSLv23_server_method());
  ctx_ = CHECK_NOTNULL(SSL_CTX_new(method));

  char const* cert = STRINGIFY(SMTP_HOME) "/smtp.pem";

  CHECK(SSL_CTX_use_certificate_file(ctx_, cert, SSL_FILETYPE_PEM) > 0)
      << "Can't load certificate file \"" << cert << "\"";
  CHECK(SSL_CTX_use_PrivateKey_file(ctx_, cert, SSL_FILETYPE_PEM) > 0)
      << "Can't load private key file \"" << cert << "\"";

  CHECK(SSL_CTX_check_private_key(ctx_))
      << "Private key does not match the public certificate";

  constexpr char dh_ike_23_pem[]
      = "-----BEGIN DH PARAMETERS-----\n"
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

  BIO* bio
      = CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(dh_ike_23_pem), -1));
  DH* dh = CHECK_NOTNULL(PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

  SSL_CTX_set_tmp_dh(ctx_, dh);

#pragma GCC diagnostic pop

  DH_free(dh);
  BIO_free(bio);

  // CHECK_EQ(1, SSL_CTX_set_cipher_list(ctx_, "!SSLv2:SSLv3:TLSv1"));
}

TLS::~TLS()
{
  if (ssl_) {
    SSL_free(ssl_);
  }
  if (ctx_) {
    EVP_cleanup();
    SSL_CTX_free(ctx_);
  }
}

void TLS::starttls(int fd_in, int fd_out, std::chrono::milliseconds timeout)
{
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

std::streamsize TLS::io_tls(char const* fnm,
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
      break;

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

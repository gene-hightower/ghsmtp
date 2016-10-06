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

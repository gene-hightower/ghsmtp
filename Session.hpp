/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#ifndef SESSION_DOT_HPP
#define SESSION_DOT_HPP

#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <experimental/string_view>

#include "Mailbox.hpp"
#include "Message.hpp"
#include "Sock.hpp"
#include "TLD.hpp"

class Session {
public:
  using parameters_t = std::unordered_map<std::string, std::string>;

  Session(Session const&) = delete;
  Session& operator=(Session const&) = delete;

  explicit Session(int fd_in = STDIN_FILENO,
                   int fd_out = STDOUT_FILENO,
                   std::string fqdn = "");

  void greeting();
  void ehlo(std::string client_identity);
  void helo(std::string client_identity);
  void mail_from(Mailbox&& reverse_path, parameters_t const& parameters);
  void rcpt_to(Mailbox&& forward_path, parameters_t const& parameters);

  bool data_start();
  void data_msg(Message& msg);
  void data_msg_done(Message& msg);

  void rset();
  void noop();
  void vrfy();
  void help();
  void quit();
  void error(std::experimental::string_view msg);
  void time();
  void starttls();

  bool timed_out() { return sock_.timed_out(); }

  std::streamsize read(char* s, std::streamsize n) { return sock_.read(s, n); }

private:
  friend struct Session_test;

  std::streamsize write_(const char* s, std::streamsize n)
  {
    return sock_.write(s, n);
  }

  std::string added_headers_(Message const& msg);

  void reset_()
  {
    reverse_path_.clear();
    forward_path_.clear();
    binarymime_ = false;
    reverse_path_verified_ = false;
  }

  bool verify_client_(std::string const& client_identity);
  bool verify_recipient_(Mailbox const& recipient);
  bool verify_sender_(Mailbox const& sender);
  bool verify_sender_domain_(std::string const& sender);
  bool verify_sender_domain_uribl_(std::string const& sender);
  bool verify_sender_spf_(Mailbox const& sender);

private:
  Sock sock_;

  std::string our_fqdn_;              // who we identify as
  std::string fcrdns_;                // who they look-up as
  std::string client_;                // (fcrdns_ [sock_.them_c_str()])
  std::string client_identity_;       // from ehlo/helo
  Mailbox reverse_path_;              // "mail from"
  std::vector<Mailbox> forward_path_; // for each "rcpt to"

  std::string received_spf_; // from libspf2

  char const* protocol_{""};

  std::random_device rd_;

  TLD tld_db_;

  bool binarymime_{false};
  bool ip_whitelisted_{false};
  bool reverse_path_verified_{false};
};

namespace Config {
constexpr size_t size = 150 * 1024 * 1024;
}

#endif // SESSION_DOT_HPP

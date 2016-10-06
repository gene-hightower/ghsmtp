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

#ifndef SESSION_DOT_HPP
#define SESSION_DOT_HPP

#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <experimental/string_view>

#include "Mailbox.hpp"
#include "Sock.hpp"

class Session {
public:
  Session(Session const&) = delete;
  Session& operator=(Session const&) = delete;

  explicit Session(int fd_in = STDIN_FILENO,
                   int fd_out = STDOUT_FILENO,
                   std::string fqdn = "");

  void greeting();
  void ehlo(std::string client_identity);
  void helo(std::string client_identity);
  void
  mail_from(Mailbox reverse_path,
            std::unordered_map<std::string, std::string> const& parameters);
  void rcpt_to(Mailbox forward_path,
               std::unordered_map<std::string, std::string> const& parameters);
  void data();
  void rset();
  void noop();
  void vrfy();
  void help();
  void quit();
  void error(std::experimental::string_view msg);
  void time();
  void starttls();

  bool timed_out() { return sock_.timed_out(); }
  std::istream& in() { return sock_.in(); }

private:
  friend struct Session_test;

  std::ostream& out_() { return sock_.out(); }

  void reset_()
  {
    reverse_path_.clear();
    forward_path_.clear();
  }

  bool verify_client_(std::string const& client_identity);
  bool verify_recipient_(Mailbox const& recipient);
  bool verify_sender_(Mailbox const& sender);
  bool verify_sender_domain_(std::string const& sender);
  bool verify_sender_domain_uribl_(std::string const& sender);
  bool verify_sender_spf_(Mailbox const& sender);

private:
  Sock sock_;

  std::string fqdn_;                  // who we identify as
  std::string fcrdns_;                // who they look-up as
  std::string client_;                // (fcrdns_ [sock_.them_c_str()])
  std::string client_identity_;       // ehlo/helo
  Mailbox reverse_path_;              // "mail from"
  std::vector<Mailbox> forward_path_; // for each "rcpt to"

  std::string received_spf_; // from libspf2

  char const* protocol_ = "";

  std::random_device rd_;

  bool reverse_path_verified_ = false;
};

#endif // SESSION_DOT_HPP

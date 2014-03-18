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

#include <algorithm>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/utsname.h>

#include "DNS.hpp"
#include "Domain.hpp"
#include "Mailbox.hpp"
#include "Message.hpp"
#include "Sock.hpp"

namespace Config {
constexpr char const* const bad_identities[] = { "illinnalum.info" };

constexpr char const* const bad_recipients[] = { "nobody", "mixmaster" };

constexpr char const* const rbls[] = { "zen.spamhaus.org",
                                       "b.barracudacentral.org" };

constexpr auto greeting_max_wait_ms = 10000;
constexpr auto greeting_min_wait_ms = 500;
}

class Session {
public:
  Session(Session const&) = delete;
  Session& operator=(Session const&) = delete;

  explicit Session(int fd_in = STDIN_FILENO, int fd_out = STDOUT_FILENO,
                   std::string const& fqdn = "");

  void greeting();
  void ehlo(std::string const& client_identity);
  void helo(std::string const& client_identity);
  void mail_from(Mailbox const& reverse_path,
                 std::unordered_map<std::string, std::string> parameters);
  void rcpt_to(Mailbox const& forward_path,
               std::unordered_map<std::string, std::string> parameters);
  void data();
  void rset();
  void noop();
  void vrfy();
  void help();
  void quit();
  void error(std::string const& msg);
  void time();
  void starttls();

  bool timed_out();
  std::istream& in();

private:
  std::ostream& out();

  void reset();
  bool verify_client(std::string const& client_identity);
  bool verify_recipient(Mailbox const& recipient);
  bool verify_sender(Mailbox const& sender);

private:
  Sock sock_;

  std::string fqdn_;                  // Who we identify as.
  std::string fcrdns_;                // Who they look-up as.
  std::string client_;                // (fcrdns_ [sock_.them_c_str()])
  std::string client_identity_;       // ehlo/helo
  Mailbox reverse_path_;              // "mail from"
  std::vector<Mailbox> forward_path_; // for each "rcpt to"

  char const* protocol_;

  std::random_device rd_;

  bool reverse_path_verified_;
};

inline Session::Session(int fd_in, int fd_out, std::string const& fqdn)
  : sock_(fd_in, fd_out)
  , fqdn_(fqdn)
  , protocol_("")
  , reverse_path_verified_(false)
{
  if (fqdn_.empty()) {
    utsname un;
    PCHECK(uname(&un) == 0);
    fqdn_ = un.nodename;

    if (fqdn_.find('.') == std::string::npos) {
      if (sock_.us_c_str()[0]) {
        std::ostringstream ss;
        ss << "[" << sock_.us_c_str() << "]";
        fqdn_ = ss.str();
      }
    } else {
      std::transform(fqdn_.begin(), fqdn_.end(), fqdn_.begin(), ::tolower);
    }
  }
}

inline void Session::greeting()
{
  // This is just a teaser, the first line of a multi-line response.
  out() << "220-" << fqdn_ << " ESMTP\r\n" << std::flush;

  if (sock_.has_peername()) {

    using namespace DNS;
    Resolver res;

    // "0.1.2.3" => "3.2.1.0."
    std::string reversed{ reverse_ip4(sock_.them_c_str()) };

    // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

    // The reverse part, check PTR records.
    std::vector<std::string> ptrs =
        get_records<RR_type::PTR>(res, reversed + "in-addr.arpa");

    char const* them = sock_.them_c_str();

    auto ptr = std::find_if(ptrs.begin(), ptrs.end(),
                            [&res, them](std::string const& s) {
      // The forward part, check each PTR for matching A record.
      std::vector<std::string> addrs = get_records<RR_type::A>(res, s);
      return std::find(addrs.begin(), addrs.end(), them) != addrs.end();
    });

    if (ptr != ptrs.end()) {
      fcrdns_ = *ptr;
      client_ = "(" + fcrdns_ + " [";
      client_ += sock_.them_c_str();
      client_ += "])";
    } else {
      client_ = "(unknown [";
      client_ += sock_.them_c_str();
      client_ += "])";
    }

    // Check with black hole lists. <https://en.wikipedia.org/wiki/DNSBL>
    for (const auto& rbl : Config::rbls) {
      if (has_record<RR_type::A>(res, reversed + rbl)) {
        out() << "421 blocked by " << rbl << "\r\n" << std::flush;
        LOG(ERROR) << client_ << " blocked by " << rbl;
        std::exit(EXIT_SUCCESS);
      }
    }

    // Wait a (random) bit of time for pre-greeting traffic.

    std::uniform_int_distribution<> uni_dist(Config::greeting_min_wait_ms,
                                             Config::greeting_max_wait_ms);

    std::chrono::milliseconds wait{ uni_dist(rd_) };

    if (sock_.input_pending(wait)) {
      out() << "421 input before greeting\r\n" << std::flush;
      LOG(ERROR) << client_ << " input before greeting";
      std::exit(EXIT_SUCCESS);
    }
  }

  out() << "220 " << fqdn_ << " ESMTP\r\n" << std::flush;
  LOG(INFO) << "connect from " << client_;
}

inline void Session::ehlo(std::string const& client_identity)
{
  protocol_ = "ESMTP";
  if (verify_client(client_identity)) {
    reset();
    out() << "250-" << fqdn_ << "\r\n"
                                "250-PIPELINING\r\n"
        //                      "250-STARTTLS\r\n"
                                "250 8BITMIME\r\n" << std::flush;
  }
}

inline void Session::helo(std::string const& client_identity)
{
  protocol_ = "SMTP";
  if (verify_client(client_identity)) {
    reset();
    out() << "250 " << fqdn_ << "\r\n" << std::flush;
  }
}

inline void
Session::mail_from(Mailbox const& reverse_path,
                   std::unordered_map<std::string, std::string> parameters)
{
  if (client_identity_.empty()) {
    out() << "503 'MAIL FROM' before 'HELO' or 'EHLO'\r\n" << std::flush;
    LOG(WARNING) << "503 'MAIL FROM' before 'HELO' or 'EHLO'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  // Take a look at the optional parameters:
  for (auto const& p : parameters) {
    if (p.first == "BODY") {
      if (p.second == "8BITMIME") {
        // everything is cool, this is our default...
      } else if (p.second == "7BIT") {
        LOG(WARNING) << "7BIT transport requested";
      } else {
        LOG(WARNING) << "unrecognized BODY type \"" << p.second
                     << "\" requested";
      }
    } else {
      LOG(WARNING) << "unrecognized MAIL FROM parameter " << p.first << "="
                   << p.second;
    }
  }

  if (verify_sender(reverse_path)) {
    reset();
    reverse_path_ = reverse_path;
    out() << "250 mail ok\r\n" << std::flush;
  }
}

inline void
Session::rcpt_to(Mailbox const& forward_path,
                 std::unordered_map<std::string, std::string> parameters)
{
  if (!reverse_path_verified_) {
    out() << "503 'RCPT TO' before 'MAIL FROM'\r\n" << std::flush;
    LOG(WARNING) << "503 'RCPT TO' before 'MAIL FROM'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  // Take a look at the optional parameters, we don't accept any:
  for (auto& p : parameters) {
    LOG(WARNING) << "unrecognized RCPT TO parameter " << p.first << "="
                 << p.second;
  }
  if (verify_recipient(forward_path)) {
    forward_path_.push_back(forward_path);
    out() << "250 rcpt ok\r\n" << std::flush;
  }
}

inline void Session::data()
{
  if (!reverse_path_verified_) {
    out() << "503 need 'MAIL FROM' before 'DATA'\r\n" << std::flush;
    LOG(WARNING) << "503 need 'MAIL FROM' before 'DATA'";
    return;
  }

  if (forward_path_.empty()) {
    out() << "554 no valid recipients\r\n" << std::flush;
    LOG(WARNING) << "554 no valid recipients";
    return;
  }

  Message msg(fqdn_, rd_);

  // The headers Return-Path, X-Original-To and Received are added to
  // the top of the message.

  std::ostringstream headers;
  headers << "Return-Path: " << reverse_path_ << std::endl;

  headers << "X-Original-To: " << forward_path_[0] << std::endl;
  for (size_t i = 1; i < forward_path_.size(); ++i) {
    headers << '\t' << forward_path_[i] << std::endl;
  }

  headers << "Received: from " << client_identity_;
  if (sock_.has_peername()) {
    headers << " " << client_;
  }
  headers << "\n\tby " << fqdn_ << " with " << protocol_ << "\n\tid "
          << msg.id() << "\n\tfor " << forward_path_[0] << ";\n\t" << msg.when()
          << "\n";

  msg.out() << headers.str();

  out() << "354 go\r\n" << std::flush;

  std::string line;

  while (std::getline(sock_.in(), line)) {

    int last = line.length() - 1;
    if ((-1 == last) || ('\r' != line.at(last))) {
      out() << "421 bare linefeed in message data\r\n" << std::flush;
      LOG(ERROR) << "421 bare linefeed in message with id " << msg.id();
      std::exit(EXIT_SUCCESS);
    }

    line.erase(last, 1); // so eat that cr

    if ("." == line) { // just a dot is <cr><lf>.<cr><lf>
      msg.save();
      LOG(INFO) << "message delivered with id " << msg.id();
      out() << "250 data ok\r\n" << std::flush;
      return;
    }

    line += '\n'; // add system standard newline
    if ('.' == line.at(0))
      line.erase(0, 1); // eat leading dot

    msg.out() << line;
  }

  if (sock_.timed_out())
    time();

  out() << "554 data NOT ok\r\n" << std::flush;
}

inline void Session::rset()
{
  reset();
  out() << "250 ok\r\n" << std::flush;
}

inline void Session::noop()
{
  out() << "250 nook\r\n" << std::flush;
}

inline void Session::vrfy()
{
  out() << "252 try it\r\n" << std::flush;
}

inline void Session::help()
{
  out() << "214-see https://digilicious.com/smtp.html\r\n"
        << "214 and https://www.ietf.org/rfc/rfc5321.txt\r\n" << std::flush;
}

inline void Session::quit()
{
  out() << "221 bye\r\n" << std::flush;
  std::exit(EXIT_SUCCESS);
}

inline void Session::error(std::string const& msg)
{
  out() << "500 command unrecognized\r\n" << std::flush;
  LOG(WARNING) << msg;
}

inline void Session::time()
{
  out() << "421 timeout\r\n" << std::flush;
  LOG(ERROR) << "timeout" << (sock_.has_peername() ? " from " : "") << client_;
  std::exit(EXIT_SUCCESS);
}

inline void Session::starttls()
{
  sock_.starttls();
}

inline bool Session::timed_out()
{
  return sock_.timed_out();
}

inline std::istream& Session::in()
{
  return sock_.in();
}

/////////////////////////////////////////////////////////////////////////////

inline std::ostream& Session::out()
{
  return sock_.out();
}

inline void Session::reset()
{
  reverse_path_.clear();
  forward_path_.clear();
}

//...........................................................................

// All of the verify_* functions send their own error messages back to
// the client.

inline bool Session::verify_client(std::string const& client_identity)
{
  if (!fcrdns_.empty() && !Domain::match(fcrdns_, client_identity)) {
    LOG(WARNING) << "this client has fcrdns " << fcrdns_ << " yet claims "
                 << client_identity;
  }
  if (DNS::is_dotted_quad(client_identity.c_str()) &&
      (client_identity != sock_.them_c_str())) {
    LOG(WARNING) << "client claiming questionable IP address "
                 << client_identity;
  }

  // Bogus clients claim to be us or some local host.
  if (Domain::match(client_identity, fqdn_) ||
      Domain::match(client_identity, "localhost") ||
      Domain::match(client_identity, "localhost.localdomain")) {
    if (strcmp(sock_.them_c_str(), "127.0.0.1")) {
      out() << "554 liar\r\n" << std::flush;
      LOG(WARNING) << "liar: client" << (sock_.has_peername() ? " " : "")
                   << client_ << " claiming " << client_identity;
      return false;
    }
  }

  for (const auto bad_identity : Config::bad_identities) {
    if (Domain::match(client_identity, bad_identity)) {
      out() << "554 bad sender\r\n" << std::flush;
      LOG(WARNING) << "bad sender" << (sock_.has_peername() ? " " : "")
                   << client_ << " claiming " << client_identity;
      return false;
    }
  }

  // Log this client
  if (sock_.has_peername()) {
    if (Domain::match(fcrdns_, client_identity)) {
      LOG(INFO) << protocol_ << " connection from " << client_;
    } else {
      LOG(INFO) << protocol_ << " connection from " << client_ << " claiming "
                << client_identity;
    }
  } else {
    LOG(INFO) << protocol_ << " connection claiming " << client_identity;
  }

  client_identity_ = client_identity;
  return true;
}

inline bool Session::verify_recipient(Mailbox const& recipient)
{
  // Make sure the domain matches.
  if (!Domain::match(recipient.domain(), fqdn_)) {
    out() << "554 relay access denied\r\n" << std::flush;
    LOG(WARNING) << "relay access denied for " << recipient;
    return false;
  }

  // Check for local addresses we reject.
  for (const auto bad_recipient : Config::bad_recipients) {
    if (0 == recipient.local_part().compare(bad_recipient)) {
      out() << "550 no such mailbox " << recipient << "\r\n" << std::flush;
      LOG(WARNING) << "no such mailbox " << recipient;
      return false;
    }
  }

  return true;
}

inline bool Session::verify_sender(Mailbox const& sender)
{
  // look up SPF & DMARC records...
  reverse_path_verified_ = true;
  return true;
}

#endif // SESSION_DOT_HPP

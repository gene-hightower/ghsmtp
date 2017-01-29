/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
*/

#include <algorithm>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/utsname.h>

#include "CDB.hpp"
#include "DNS.hpp"
#include "Domain.hpp"
#include "IP4.hpp"
#include "Message.hpp"
#include "SPF.hpp"
#include "Session.hpp"

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>

namespace Config {
constexpr char const* const bad_recipients[] = {
    "a",         "ene",    "h.gene",   "jay",         "lizard",
    "mixmaster", "nobody", "oq6_2nbq", "truthfinder",
};

constexpr char const* const rbls[] = {
    "zen.spamhaus.org", "b.barracudacentral.org",
};

constexpr char const* const uribls[] = {
    "dbl.spamhaus.org", "black.uribl.com", "multi.surbl.org",
};

constexpr auto greeting_max_wait_ms = 10'000;
constexpr auto greeting_min_wait_ms = 500;
}

using namespace std::string_literals;

Session::Session(int fd_in, int fd_out, std::string our_fqdn)
  : sock_(fd_in, fd_out)
  , our_fqdn_{std::move(our_fqdn)}
{
  if (our_fqdn_.empty()) {
    utsname un;
    PCHECK(uname(&un) == 0);
    our_fqdn_ = un.nodename;

    if (our_fqdn_.find('.') == std::string::npos) {
      if (sock_.us_c_str()[0]) {
        our_fqdn_ = "["s + sock_.us_c_str() + "]"s;
      }
    }
    else {
      std::transform(our_fqdn_.begin(), our_fqdn_.end(), our_fqdn_.begin(),
                     ::tolower);
    }
  }
}

void Session::greeting()
{
  if (sock_.has_peername()) {

    CDB black("ip-black");
    if (black.lookup(sock_.them_c_str())) {
      char rply[] = "421 4.7.1 IP address blacklisted\r\n";
      write_(rply, sizeof(rply) - 1);
      // LOG(ERROR) << "IP address " << sock_.them_c_str() << " blacklisted";
      std::exit(EXIT_SUCCESS);
    }

    // LOG(INFO) << "connect from " << sock_.them_c_str();

    // This is just a teaser, the first line of a multi-line response.
    auto rply = "220-"s + our_fqdn_ + " ESMTP ghsmtp\r\n"s;
    write_(rply.data(), rply.size());

    using namespace DNS;
    Resolver res;

    // "0.1.2.3" => "3.2.1.0."
    std::string reversed{IP4::reverse(sock_.them_c_str())};

    // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

    // The reverse part, check PTR records.
    std::vector<std::string> ptrs
        = get_records<RR_type::PTR>(res, reversed + "in-addr.arpa");

    char const* them = sock_.them_c_str();

    auto ptr = std::find_if(
        ptrs.begin(), ptrs.end(), [&res, them](std::string const& s) {
          // The forward part, check each PTR for matching A record.
          std::vector<std::string> addrs = get_records<RR_type::A>(res, s);
          return std::find(addrs.begin(), addrs.end(), them) != addrs.end();
        });

    if (ptr != ptrs.end()) {
      fcrdns_ = *ptr;
      client_ = fcrdns_ + " [" + sock_.them_c_str() + "]";
      // LOG(INFO) << "connect from " << fcrdns_;
    }
    else {
      client_ = std::string("unknown [") + sock_.them_c_str() + "]";
    }

    CDB white("ip-white");
    if (white.lookup(sock_.them_c_str())) {
      LOG(INFO) << "IP address " << sock_.them_c_str() << " whitelisted";
      ip_whitelisted_ = true;
    }
    else {
      // Check with black hole lists. <https://en.wikipedia.org/wiki/DNSBL>
      for (const auto& rbl : Config::rbls) {
        if (has_record<RR_type::A>(res, reversed + rbl)) {
          auto rply = "421 4.7.1 blocked by "s + rbl + "\r\n"s;
          write_(rply.data(), rply.size());
          // LOG(ERROR) << client_ << " blocked by " << rbl;
          std::exit(EXIT_SUCCESS);
        }
      }
      // LOG(INFO) << "IP address " << sock_.them_c_str() << " not blacklisted";
    }

    // Wait a (random) bit of time for pre-greeting traffic.
    std::uniform_int_distribution<> uni_dist(Config::greeting_min_wait_ms,
                                             Config::greeting_max_wait_ms);
    std::chrono::milliseconds wait{uni_dist(rd_)};

    if (sock_.input_ready(wait)) {
      char rply[] = "421 4.5.0 input before greeting\r\n";
      write_(rply, sizeof(rply) - 1);
      // LOG(ERROR) << client_ << " input before greeting";
      std::exit(EXIT_SUCCESS);
    }
  } // if (sock_.has_peername())

  auto rply = "220 "s + our_fqdn_ + " ESMTP ghsmtp\r\n"s;
  write_(rply.data(), rply.size());

  LOG(INFO) << "connect from " << client_;
}

void Session::ehlo(std::string client_identity)
{
  protocol_ = sock_.tls() ? "ESMTPS" : "ESMTP";

  if (!verify_client_(client_identity)) {
    std::exit(EXIT_SUCCESS);
  }

  reset_();
  client_identity_ = std::move(client_identity);

  std::ostringstream out;
  out << "250-" << our_fqdn_ << "\r\n";

  // RFC 1870
  out << "250-SIZE " << Config::size << "\r\n";

  // RFC 6152
  out << "250-8BITMIME\r\n";

  // If we're not already TLS, offer TLS
  if (!sock_.tls()) {
    // RFC 3207
    out << "250-STARTTLS\r\n";
  }

  // RFC 2034
  out << "250-ENHANCEDSTATUSCODES\r\n";

  // RFC 2920
  out << "250-PIPELINING\r\n";

  // RFC 3030
  // out << "250-CHUNKING\r\n";

  // RFC 6531
  out << "250 SMTPUTF8\r\n";

  auto out_str = out.str();
  write_(out_str.data(), out_str.size());
}

void Session::helo(std::string client_identity)
{
  protocol_ = "SMTP";

  if (!verify_client_(client_identity)) {
    std::exit(EXIT_SUCCESS);
  }

  reset_();
  client_identity_ = std::move(client_identity);

  auto rply = "250 "s + our_fqdn_ + "\r\n"s;
  write_(rply.data(), rply.size());
}

void Session::mail_from(Mailbox&& reverse_path, parameters_t const& parameters)
{
  if (client_identity_.empty()) {
    char rply[] = "503 5.5.1 'MAIL FROM' before 'HELO' or 'EHLO'\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(WARNING) << "'MAIL FROM' before 'HELO' or 'EHLO'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  // Take a look at the optional parameters:
  for (auto const& p : parameters) {
    std::string name = p.first;
    std::transform(name.begin(), name.end(), name.begin(), ::toupper);

    std::string val = p.second;
    std::transform(val.begin(), val.end(), val.begin(), ::toupper);

    if (name == "BODY") {
      if (val == "8BITMIME") {
        // everything is cool, this is our default...
      }
      else if (val == "7BIT") {
        LOG(WARNING) << "7BIT transport requested";
      }
      else if (val == "BINARYMIME") {
        LOG(WARNING) << "BINARYMIME transport requested";
        binarymime_ = true;
      }
      else {
        LOG(WARNING) << "unrecognized BODY type \"" << val << "\" requested";
      }
    }
    else if (name == "SMTPUTF8") {
      if (!val.empty()) {
        LOG(WARNING) << "SMTPUTF8 parameter has a value: " << val;
      }
    }
    else if (name == "SIZE") {
      if (val.empty()) {
        LOG(WARNING) << "SIZE parameter has no value.";
      }
      else {
        try {
          size_t sz = stoll(val);
          if (sz > Config::size) {
            char rply[] = "552 5.3.4 message size exceeds fixed maximium "
                          "message size\r\n";
            write_(rply, sizeof(rply) - 1);
            LOG(WARNING) << "SIZE parameter too large: " << sz;
            return;
          }
        }
        catch (std::invalid_argument const& e) {
          LOG(WARNING) << "SIZE parameter has invalid value: " << p.second;
        }
        catch (std::out_of_range const& e) {
          LOG(WARNING) << "SIZE parameter has out-of-range value: " << p.second;
        }
        // I guess we just ignore bad size parameters.
      }
    }
    else {
      LOG(WARNING) << "unrecognized MAIL FROM parameter " << name << "=" << val;
    }
  }

  if (verify_sender_(reverse_path)) {
    reset_();
    reverse_path_ = std::move(reverse_path);
    char rply[] = "250 2.1.0 mail ok\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(INFO) << "MAIL FROM " << reverse_path_;
  }
  else {
    std::exit(EXIT_SUCCESS);
  }
}

void Session::rcpt_to(Mailbox&& forward_path, parameters_t const& parameters)
{
  if (!reverse_path_verified_) {
    char rply[] = "503 5.5.1 'RCPT TO' before 'MAIL FROM'\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(WARNING) << "'RCPT TO' before 'MAIL FROM'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  // Take a look at the optional parameters, we don't accept any:
  for (auto& p : parameters) {
    LOG(WARNING) << "unrecognized 'RCPT TO' parameter " << p.first << "="
                 << p.second;
  }

  if (verify_recipient_(forward_path)) {
    forward_path_.push_back(std::move(forward_path));
    char rply[] = "250 2.1.5 OK\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(INFO) << "RCPT TO " << forward_path_.back();
  }
  // We're lenient on most bad recipients, no else/exit here.
}

bool Session::data_start()
{
  if (binarymime_) {
    char rply[] = "503 5.5.1 DATA does not support BINARYMIME\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "DATA does not support BINARYMIME";
    return false;
  }
  if (!reverse_path_verified_) {
    char rply[] = "503 5.5.1 need 'MAIL FROM' before 'DATA'\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "need 'MAIL FROM' before 'DATA'";
    return false;
  }
  if (forward_path_.empty()) {
    char rply[] = "503 5.5.1 need 'RCPT TO' before 'DATA'\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "no valid recipients";
    return false;
  }
  char rply[] = "354 go, end with <CR><LF>.<CR><LF>\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "DATA";
  return true;
}

std::string Session::added_headers_(Message const& msg)
{
  // The headers Return-Path, X-Original-To, Received and Received-SPF
  // are returned as a string.

  std::ostringstream headers;
  headers << "Return-Path: <" << reverse_path_ << ">\n";
  headers << "X-Original-To: <" << forward_path_[0] << ">\n";
  for (size_t i = 1; i < forward_path_.size(); ++i) {
    headers << "\t<" << forward_path_[i] << ">\n";
  }
  headers << "Received: from " << client_identity_;
  if (sock_.has_peername()) {
    headers << " (" << client_ << ")";
  }
  headers << "\n\tby " << our_fqdn_ << " with " << protocol_ << " id "
          << msg.id() << "\n\tfor <" << forward_path_[0] << '>';

  std::string tls_info{sock_.tls_info()};
  if (tls_info.length()) {
    headers << "\n\t(" << tls_info << ")";
  }
  headers << ";\n\t" << msg.when() << "\n";

  // Received-SPF:
  if (!received_spf_.empty()) {
    headers << received_spf_ << "\n";
  }

  return headers.str();
}

void Session::data_msg(Message& msg) // called /after/ data_start
{
  auto status = Message::SpamStatus::spam;

  // Anything enciphered tastes a lot like ham.
  if (sock_.tls()) {
    status = Message::SpamStatus::ham;
  }

  char const* tld = tld_db_.get_registered_domain(client_identity_.c_str());
  if (!tld) {
    tld = client_identity_.c_str();
  }
  CDB white("white");
  if (white.lookup(tld)) {
    status = Message::SpamStatus::ham;
  }

  // I will allow this as sort of the gold standard for naming.
  if (client_identity_ == fcrdns_) {
    status = Message::SpamStatus::ham;
  }

  msg.open(our_fqdn_, status);

  // The headers Return-Path, X-Original-To, Received and Received-SPF
  // are added to the top of the message.

  msg.out() << added_headers_(msg);
}

void Session::data_msg_done(Message& msg)
{
  msg.save();
  LOG(INFO) << "message delivered with id " << msg.id();
  char rply[] = "250 2.0.0 OK\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "end DATA";
}

void Session::rset()
{
  reset_();
  char rply[] = "250 2.0.0 OK\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "RSET";
}

void Session::noop()
{
  char rply[] = "250 2.0.0 OK\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "NOOP";
}

void Session::vrfy()
{
  char rply[] = "252 2.0.0 try it\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "VRFY";
}

void Session::help()
{
  char rply[] = "214-see https://digilicious.com/smtp.html\r\n"
                "214 and https://www.ietf.org/rfc/rfc5321.txt\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "HELP";
}

void Session::quit()
{
  char rply[] = "221 2.0.0 bye\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(INFO) << "QUIT";
  std::exit(EXIT_SUCCESS);
}

void Session::error(std::experimental::string_view m)
{
  char rply[] = "502 5.2.2 command unrecognized\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(ERROR) << m;
}

void Session::time()
{
  char rply[] = "421 4.4.2 timeout\r\n";
  write_(rply, sizeof(rply) - 1);
  LOG(ERROR) << "timeout" << (sock_.has_peername() ? " from " : "") << client_;
  std::exit(EXIT_SUCCESS);
}

void Session::starttls()
{
  if (sock_.tls()) {
    char rply[] = "554 5.5.1 TLS already active\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "STARTTLS issued with TLS already active";
  }
  else {
    char rply[] = "220 2.0.0 go for TLS\r\n";
    write_(rply, sizeof(rply) - 1);
    sock_.starttls();
    LOG(INFO) << "STARTTLS " << sock_.tls_info();
  }
}

/////////////////////////////////////////////////////////////////////////////

// All of the verify_* functions send their own error messages back to
// the client on failure, and return false.  The exception is the very
// bad recipient list that exits right away.

bool Session::verify_client_(std::string const& client_identity)
// check the identity from the HELO/EHLO
{
  if (IP4::is_bracket_address(client_identity)) {
    char rply[] = "421 4.7.1 need domain name\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "need domain name not " << client_identity;
    return false;
  }

  // Bogus clients claim to be us or some local host.
  if (Domain::match(client_identity, our_fqdn_)
      || Domain::match(client_identity, "localhost")
      || Domain::match(client_identity, "localhost.localdomain")
      || Domain::match(client_identity, "[127.0.0.1]")) {

    if (!Domain::match(our_fqdn_, fcrdns_)
        && strcmp(sock_.them_c_str(), "127.0.0.1")) {
      char rply[] = "421 4.7.1 liar\r\n";
      write_(rply, sizeof(rply) - 1);
      LOG(ERROR) << "liar: client" << (sock_.has_peername() ? " " : "")
                 << client_ << " claiming " << client_identity;
      return false;
    }
  }

  std::vector<std::string> labels;
  boost::algorithm::split(labels, client_identity,
                          boost::algorithm::is_any_of("."));

  if (labels.size() < 2) {
    char rply[] = "421 4.1.8 invalid sender system address\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "invalid sender" << (sock_.has_peername() ? " " : "")
               << client_ << " claiming " << client_identity;
    return false;
  }

  CDB black("black");
  if (black.lookup(client_identity)) {
    char rply[] = "421 4.7.1 blacklisted identity\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(ERROR) << "blacklisted identity" << (sock_.has_peername() ? " " : "")
               << client_ << " claiming " << client_identity;
    return false;
  }
  else {
    LOG(INFO) << "unblack client identity " << client_identity;
  }

  char const* tld = tld_db_.get_registered_domain(client_identity.c_str());
  if (!tld) {
    tld = client_identity.c_str();
  }
  else {
    if (black.lookup(tld)) {
      char rply[] = "421 4.7.0 blacklisted identity\r\n";
      write_(rply, sizeof(rply) - 1);
      LOG(ERROR) << "blacklisted TLD" << (sock_.has_peername() ? " " : "")
                 << client_ << " claiming " << client_identity;
      return false;
    }
    else {
      LOG(INFO) << "unblack TLD " << tld;
    }
  }

  // At this point, check whois for tld, if it's less than 48 hours
  // old, we may want to take action.

  // Log this client
  if (sock_.has_peername()) {
    if (Domain::match(fcrdns_, client_identity)) {
      LOG(INFO) << protocol_ << " connection from " << client_;
    }
    else {
      LOG(INFO) << protocol_ << " connection from " << client_ << " claiming "
                << client_identity;
    }
  }
  else {
    LOG(INFO) << protocol_ << " connection claiming " << client_identity;
  }

  return true;
}

bool Session::verify_recipient_(Mailbox const& recipient)
{
  if ((recipient.local_part() == "Postmaster") && (recipient.domain() == "")) {
    LOG(INFO) << "magic Postmaster address";
    return true;
  }

  // Make sure the domain matches.
  if (!Domain::match(recipient.domain(), our_fqdn_)) {
    char rply[] = "554 5.1.2 relay access denied\r\n";
    write_(rply, sizeof(rply) - 1);
    LOG(WARNING) << "relay access denied for " << recipient;
    return false;
  }

  // Check for local addresses we reject.
  for (const auto bad_recipient : Config::bad_recipients) {
    if (0 == recipient.local_part().compare(bad_recipient)) {
      auto rply = "550 5.1.1 bad recipient "s
                  + static_cast<std::string>(recipient) + "\r\n"s;
      write_(rply.data(), rply.size());
      LOG(WARNING) << "bad recipient " << recipient;
      return false;
    }
  }

  return true;
}

bool Session::verify_sender_(Mailbox const& sender)
{
  // If the reverse path domain matches the Forward-confirmed reverse
  // DNS of the sending IP address, we skip the uribl check.
  if (!Domain::match(sender.domain(), fcrdns_)) {
    if (!verify_sender_domain_(sender.domain()))
      return false;
  }

  if (sock_.has_peername() && !ip_whitelisted_) {
    if (!verify_sender_spf_(sender))
      return false;
  }

  return reverse_path_verified_ = true;
}

bool Session::verify_sender_domain_(std::string const& sender)
{
  if (sender.empty()) {
    // MAIL FROM:<>
    // is used to send bounce messages.
    return true;
  }

  std::string domain = sender;
  std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

  // Break sender domain into labels:

  std::vector<std::string> labels;
  boost::algorithm::split(labels, domain, boost::algorithm::is_any_of("."));

  if (labels.size() < 2) { // This is not a valid domain.
    auto rply = "421 5.7.1 invalid sender domain "s + domain + "\r\n"s;
    write_(rply.data(), rply.size());
    LOG(ERROR) << "sender \"" << domain << "\" invalid syntax";
    return false;
  }

  CDB white("white");
  if (white.lookup(domain)) {
    LOG(INFO) << "sender \"" << domain << "\" whitelisted";
    return true;
  }

  char const* tld = tld_db_.get_registered_domain(domain.c_str());
  if (!tld) {
    tld = domain.c_str();
  }
  if (white.lookup(tld)) {
    LOG(INFO) << "sender tld \"" << tld << "\" whitelisted";
    return true;
  }

  // Based on <http://www.surbl.org/guidelines>

  std::string two_level
      = labels[labels.size() - 2] + "." + labels[labels.size() - 1];

  if (labels.size() > 2) {
    std::string three_level = labels[labels.size() - 3] + "." + two_level;

    CDB three_tld("three-level-tlds");
    if (three_tld.lookup(three_level.c_str())) {
      if (labels.size() > 3) {
        return verify_sender_domain_uribl_(labels[labels.size() - 4] + "."
                                           + three_level);
      }
      else {
        char rply[] = "421 4.7.1 bad sender domain\r\n";
        write_(rply, sizeof(rply) - 1);
        LOG(ERROR) << "sender \"" << sender
                   << "\" blocked by exact match on three-level-tlds list";
        return false;
      }
    }
  }

  CDB two_tld("two-level-tlds");
  if (two_tld.lookup(two_level.c_str())) {
    if (labels.size() > 2) {
      return verify_sender_domain_uribl_(labels[labels.size() - 3] + "."
                                         + two_level);
    }
    else {
      char rply[] = "421 4.7.1 bad sender domain\r\n";
      write_(rply, sizeof(rply) - 1);
      LOG(ERROR) << "sender \"" << sender
                 << "\" blocked by exact match on two-level-tlds list";
      return false;
    }
  }

  if (two_level.compare(tld)) {
    LOG(INFO) << "two level " << two_level << " != tld " << tld;
  }

  return verify_sender_domain_uribl_(tld);
}

bool Session::verify_sender_domain_uribl_(std::string const& sender)
{
  DNS::Resolver res;
  for (const auto& uribl : Config::uribls) {
    if (DNS::has_record<DNS::RR_type::A>(res, (sender + ".") + uribl)) {
      auto rply = "421 4.7.1 blocked by "s + uribl + "\r\n"s;
      write_(rply.data(), rply.size());
      LOG(ERROR) << sender << " blocked by " << uribl;
      return false;
    }
  }

  LOG(INFO) << sender << " cleared by URIBLs";
  return true;
}

bool Session::verify_sender_spf_(Mailbox const& sender)
{
  // address literal skips SPF test
  if (!client_identity_.empty() && client_identity_[0] == '[')
    return true;

  SPF::Server spf_srv(our_fqdn_.c_str());
  SPF::Request spf_req(spf_srv);

  spf_req.set_ipv4_str(sock_.them_c_str());
  spf_req.set_helo_dom(client_identity_.c_str());

  auto from = boost::lexical_cast<std::string>(sender);

  spf_req.set_env_from(from.c_str());

  SPF::Response spf_res(spf_req);

  if (spf_res.result() == SPF::Result::FAIL) {
    auto rply = "421 4.7.23 "s + spf_res.smtp_comment() + "\r\n"s;
    write_(rply.data(), rply.size());
    LOG(ERROR) << spf_res.header_comment();
    return false;
  }

  LOG(INFO) << spf_res.header_comment();
  received_spf_ = spf_res.received_spf();
  return true;
}

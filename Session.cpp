#include <algorithm>
#include <charconv>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "DNS.hpp"
#include "Domain.hpp"
#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "MessageStore.hpp"
#include "Session.hpp"
#include "esc.hpp"
#include "iequal.hpp"
#include "is_ascii.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include <boost/xpressive/xpressive.hpp>

#include <syslog.h>

DEFINE_string(selector, "ghsmtp", "DKIM selector");

using namespace std::string_literals;

namespace Config {
char const* wls[]{
    "list.dnswl.org",
};

/*
<https://www.dnswl.org/?page_id=15#query>

Return codes

The return codes are structured as 127.0.x.y, with “x” indicating the category
of an entry and “y” indicating how trustworthy an entry has been judged.

Categories (127.0.X.y):

    2 – Financial services
    3 – Email Service Providers
    4 – Organisations (both for-profit [ie companies] and non-profit)
    5 – Service/network providers
    6 – Personal/private servers
    7 – Travel/leisure industry
    8 – Public sector/governments
    9 – Media and Tech companies
    10 – some special cases
    11 – Education, academic
    12 – Healthcare
    13 – Manufacturing/Industrial
    14 – Retail/Wholesale/Services
    15 – Email Marketing Providers
    20 – Added through Self Service without specific category

Trustworthiness / Score (127.0.x.Y):

    0 = none – only avoid outright blocking (eg large ESP mailservers, -0.1)
    1 = low – reduce chance of false positives (-1.0)
    2 = medium – make sure to avoid false positives but allow override for clear
cases (-10.0) 3 = high – avoid override (-100.0).

The scores in parantheses are typical SpamAssassin scores.

Special return code 127.0.0.255

In cases where your nameserver issues more than 100’000 queries / 24 hours, you
may be blocked from further queries. The return code “127.0.0.255” indicates
this situation.

*/

char const* bls[]{
    "b.barracudacentral.org",
    "sbl.spamhaus.org",
};

/*** Last octet from A record returned by blocklists ***

From <http://uribl.com/about.shtml#implementation>

X   Binary    On List
---------------------------------------------------------
1   00000001  Query blocked, possibly due to high volume
2   00000010  black
4   00000100  grey
8   00001000  red
14  00001110  black,grey,red (for testpoints)

From <https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291>

Return Codes 	Data Source
127.0.1.2 	spam domain
127.0.1.4 	phish domain
127.0.1.5 	malware domain
127.0.1.6 	botnet C&C domain
127.0.1.102 	abused legit spam
127.0.1.103 	abused spammed redirector domain
127.0.1.104 	abused legit phish
127.0.1.105 	abused legit malware
127.0.1.106 	abused legit botnet C&C
127.0.1.255 	IP queries prohibited!

From <http://www.surbl.org/lists#multi>

last octet indicates which lists it belongs to. The bit positions in
that last octet for membership in the different lists are:

  8 = listed on PH
 16 = listed on MW
 64 = listed on ABUSE
128 = listed on CR

*/

char const* uribls[]{
    "dbl.spamhaus.org",
    "multi.uribl.com",
};

constexpr auto greeting_wait              = std::chrono::seconds{2};
constexpr int  max_recipients_per_message = 100;
constexpr int  max_unrecognized_cmds      = 20;

// Read timeout value gleaned from RFC-1123 section 5.3.2 and RFC-5321
// section 4.5.3.2.7.
constexpr auto read_timeout  = std::chrono::minutes{5};
constexpr auto write_timeout = std::chrono::seconds{30};
} // namespace Config

#include <gflags/gflags.h>

DEFINE_bool(test_mode, false, "ease up on some checks");

DEFINE_bool(immortal, false, "don't set process timout");

DEFINE_uint64(max_read, 0, "max data to read");
DEFINE_uint64(max_write, 0, "max data to write");

DEFINE_bool(rrvs, false, "support RRVS à la RFC 7293");

Session::Session(fs::path                  config_path,
                 std::function<void(void)> read_hook,
                 int                       fd_in,
                 int                       fd_out)
  : config_path_(config_path)
  , res_(config_path)
  , sock_(fd_in, fd_out, read_hook, Config::read_timeout, Config::write_timeout)
//, send_(config_path, "smtp")
//, srs_(config_path)
{
  auto accept_db_name  = config_path_ / "accept_domains";
  auto allow_db_name   = config_path_ / "allow";
  auto block_db_name   = config_path_ / "block";
  auto forward_db_name = config_path_ / "forward";

  accept_domains_.open(accept_db_name);
  allow_.open(allow_db_name);
  block_.open(block_db_name);
  forward_.open(forward_db_name);

  if (sock_.has_peername() && !IP::is_private(sock_.us_c_str())) {
    auto fcrdns = DNS::fcrdns(res_, sock_.us_c_str());
    for (auto const& fcr : fcrdns) {
      server_fcrdns_.emplace_back(fcr);
    }
  }

  server_identity_ = [this] {
    auto const id_from_env{getenv("GHSMTP_SERVER_ID")};
    if (id_from_env)
      return std::string{id_from_env};

    auto const hostname{osutil::get_hostname()};
    if (hostname.find('.') != std::string::npos)
      return hostname;

    if (!server_fcrdns_.empty()) {
      // first result should be shortest
      return server_fcrdns_.front().ascii();
    }

    auto const us_c_str = sock_.us_c_str();
    if (us_c_str && !IP::is_private(us_c_str)) {
      return IP::to_address_literal(us_c_str);
    }

    LOG(FATAL) << "can't determine my server ID, set GHSMTP_SERVER_ID maybe";
    return ""s;
  }();

  // send_.set_sender(server_identity_);

  max_msg_size(Config::max_msg_size_initial);
}

void Session::max_msg_size(size_t max)
{
  max_msg_size_ = max; // number to advertise via RFC 1870

  if (FLAGS_max_read) {
    sock_.set_max_read(FLAGS_max_read);
  }
  else {
    auto const overhead = std::max(max / 10, size_t(2048));
    sock_.set_max_read(max + overhead);
  }
}

void Session::bad_host_(char const* msg) const
{
  if (sock_.has_peername()) {
    // On my systems, this pattern triggers a fail2ban rule that
    // blocks connections from this IP address on port 25 for a few
    // days.  See <https://www.fail2ban.org/> for more info.
    syslog(LOG_MAIL | LOG_WARNING, "bad host [%s] %s", sock_.them_c_str(), msg);
  }
  std::exit(EXIT_SUCCESS);
}

void Session::reset_()
{
  // RSET does not force another EHLO/HELO, the one piece of per
  // transaction data saved is client_identity_:

  // client_identity_.clear(); <-- not cleared!

  reverse_path_.clear();
  forward_path_.clear();
  spf_received_.clear();
  // fwd_path_.clear();
  // fwd_from_.clear();
  // rep_info_.clear();

  binarymime_ = false;
  smtputf8_   = false;
  // prdr_     = false;

  if (msg_) {
    msg_.reset();
  }

  max_msg_size(max_msg_size());

  state_ = xact_step::mail;
  // send_.rset();
}

// Return codes from connection establishment are 220 or 554, according
// to RFC 5321.  That's it.

void Session::greeting()
{
  CHECK(state_ == xact_step::helo);

  if (sock_.has_peername()) {
    close(2); // if we're a networked program, never send to stderr

    std::string error_msg;
    if (!verify_ip_address_(error_msg)) {
      // no glog message at this point
      bad_host_(error_msg.c_str());
    }

    /******************************************************************
    <https://tools.ietf.org/html/rfc5321#section-4.3.1> says:

    4.3.  Sequencing of Commands and Replies

    4.3.1.  Sequencing Overview

    The communication between the sender and receiver is an alternating
    dialogue, controlled by the sender.  As such, the sender issues a
    command and the receiver responds with a reply.  Unless other
    arrangements are negotiated through service extensions, the sender
    MUST wait for this response before sending further commands.  One
    important reply is the connection greeting.  Normally, a receiver
    will send a 220 "Service ready" reply when the connection is
    completed.  The sender SHOULD wait for this greeting message before
    sending any commands.

    So which is it?

    “…the receiver responds with a reply.”
    “…the sender MUST wait for this response…”
    “One important reply is the connection greeting.”
    “The sender SHOULD wait for this greeting…”

    So is it MUST or SHOULD?  I enforce MUST.
    *******************************************************************/

    // Wait a bit of time for pre-greeting traffic.
    if (!(ip_allowed_ || fcrdns_allowed_)) {
      if (sock_.input_ready(Config::greeting_wait)) {
        out_() << "421 4.3.2 not accepting network messages\r\n" << std::flush;
        // no glog message at this point
        bad_host_("input before any greeting");
      }
      // Give a half greeting and wait again.
      out_() << "220-" << server_id_() << " ESMTP - ghsmtp\r\n" << std::flush;
      if (sock_.input_ready(Config::greeting_wait)) {
        out_() << "421 4.3.2 not accepting network messages\r\n" << std::flush;
        // LOG(INFO) << "half greeting got " << client_;
        bad_host_("input before full greeting");
      }
    }
    LOG(INFO) << "connect from " << client_;
  }

  out_() << "220 " << server_id_() << " ESMTP - ghsmtp\r\n" << std::flush;

  if ((!FLAGS_immortal) && (getenv("GHSMTP_IMMORTAL") == nullptr)) {
    alarm(2 * 60); // initial alarm
  }
}

void Session::flush() { out_() << std::flush; }

void Session::last_in_group_(std::string_view verb)
{
  if (sock_.input_ready(std::chrono::seconds(0))) {
    LOG(WARNING) << "pipelining error; input ready processing " << verb;
  }
}

void Session::check_for_pipeline_error_(std::string_view verb)
{
  if (!extensions_ && sock_.input_ready(std::chrono::seconds(0))) {
    LOG(WARNING) << "pipelining error; input ready processing " << verb;
  }
}

void Session::lo_(char const* verb, std::string_view client_identity)
{
  last_in_group_(verb);
  reset_();

  if (client_identity_ != client_identity) {
    client_identity_ = client_identity;

    std::string error_msg;
    if (!verify_client_(client_identity_, error_msg)) {
      bad_host_(error_msg.c_str());
    }
  }

  if (*verb == 'H') {
    extensions_ = false;
    out_() << "250 " << server_id_() << "\r\n";
  }

  if (*verb == 'E') {
    extensions_ = true;

    if (sock_.has_peername()) {
      out_() << "250-" << server_id_() << " at your service, " << client_
             << "\r\n";
    }
    else {
      out_() << "250-" << server_id_() << "\r\n";
    }

    out_() << "250-SIZE " << max_msg_size() << "\r\n"; // RFC 1870
    out_() << "250-8BITMIME\r\n";                      // RFC 6152

    if (FLAGS_rrvs) {
      out_() << "250-RRVS\r\n"; // RFC 7293
    }

    // out_() << "250-PRDR\r\n"; // draft-hall-prdr-00.txt

    if (sock_.tls()) {
      // Check sasl sources for auth types.
      // out_() << "250-AUTH PLAIN\r\n";
      out_() << "250-REQUIRETLS\r\n"; // RFC 8689
    }
    else {
      // If we're not already TLS, offer TLS
      out_() << "250-STARTTLS\r\n"; // RFC 3207
    }
    out_() << "250-ENHANCEDSTATUSCODES\r\n" // RFC 2034
              "250-PIPELINING\r\n"          // RFC 2920
              "250-BINARYMIME\r\n"          // RFC 3030
              "250-CHUNKING\r\n"            // RFC 3030
              "250 SMTPUTF8\r\n";           // RFC 6531
  }

  out_() << std::flush;

  if (sock_.has_peername()) {
    if (std::find(begin(client_fcrdns_), end(client_fcrdns_),
                  client_identity_) != end(client_fcrdns_)) {
      LOG(INFO) << verb << " " << client_identity << " from "
                << sock_.them_address_literal();
    }
    else {
      LOG(INFO) << verb << " " << client_identity << " from " << client_;
    }
  }
  else {
    LOG(INFO) << verb << " " << client_identity;
  }
}

void Session::mail_from(Mailbox&& reverse_path, parameters_t const& parameters)
{
  check_for_pipeline_error_("MAIL FROM");

  switch (state_) {
  case xact_step::helo:
    out_() << "503 5.5.1 sequence error, expecting HELO/EHLO\r\n" << std::flush;
    LOG(WARNING) << "'MAIL FROM' before HELO/EHLO"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::mail: break;
  case xact_step::rcpt:
    out_() << "503 5.5.1 sequence error, expecting RCPT\r\n" << std::flush;
    LOG(WARNING) << "nested MAIL command"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::data:
  case xact_step::bdat:
    out_() << "503 5.5.1 sequence error, expecting DATA/BDAT\r\n" << std::flush;
    LOG(WARNING) << "nested MAIL command"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::rset:
    out_() << "503 5.5.1 sequence error, expecting RSET\r\n" << std::flush;
    LOG(WARNING) << "error state must be cleared with a RSET"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  if (!verify_from_params_(parameters)) {
    return;
  }

  if (!smtputf8_ && !is_ascii(reverse_path.local_part())) {
    LOG(WARNING) << "non ascii reverse_path \"" << reverse_path
                 << "\" without SMTPUTF8 paramater";
  }

  std::string error_msg;
  if (!verify_sender_(reverse_path, error_msg)) {
    LOG(WARNING) << "verify sender failed: " << error_msg;
    bad_host_(error_msg.c_str());
  }

  reverse_path_ = std::move(reverse_path);
  // fwd_path_.clear();
  // fwd_from_.clear();
  forward_path_.clear();
  out_() << "250 2.1.0 MAIL FROM OK\r\n";
  // No flush RFC-2920 section 3.1, this could be part of a command group.

  fmt::memory_buffer params;
  for (auto const& [name, value] : parameters) {
    fmt::format_to(params, " {}", name);
    if (!value.empty()) {
      fmt::format_to(params, "={}", value);
    }
  }
  LOG(INFO) << "MAIL FROM:<" << reverse_path_ << ">" << fmt::to_string(params);

  state_ = xact_step::rcpt;
}

// bool Session::forward_to_(std::string const& forward, Mailbox const& rcpt_to)
// {
//   // If we're already forwarding or replying, reject
//   if (!fwd_path_.empty() || !rep_info_.empty()) {
//     out_() << "432 4.3.0 Recipient's incoming mail queue has been
//     stopped\r\n"
//            << std::flush;
//     LOG(WARNING) << "failed to forward to <" << forward
//                  << "> already forwarding or replying for: " << rcpt_to;
//     return false;
//   }

//   fwd_path_ = Mailbox(forward);
//   fwd_from_ = rcpt_to;

//   // New bounce address
//   Reply::from_to bounce;
//   bounce.mail_from = reverse_path_.as_string();

//   auto const new_bounce = srs_.enc_bounce(bounce, server_id_().c_str());

//   auto const mail_from = Mailbox(new_bounce);

//   std::string error_msg;
//   if (!send_.mail_from_rcpt_to(res_, mail_from, fwd_path_, error_msg)) {
//     out_() << error_msg << std::flush;
//     LOG(WARNING) << "failed to forward <" << fwd_path_ << "> " << error_msg;
//     return false;
//   }

//   LOG(INFO) << "RCPT TO:<" << rcpt_to << "> forwarding to == <" << fwd_path_
//             << ">";
//   return true;
// }

// bool Session::reply_to_(Reply::from_to const& reply_info, Mailbox const&
// rcpt_to)
// {
//   // If we're already forwarding or replying, reject
//   if (!fwd_path_.empty() || !rep_info_.empty()) {
//     out_() << "432 4.3.0 Recipient's incoming mail queue has been
//     stopped\r\n"
//            << std::flush;
//     LOG(WARNING) << "failed to reply to <" << reply_info.mail_from
//                  << "> already forwarding or replying for: " << rcpt_to;
//     return false;
//   }

//   rep_info_ = reply_info;

//   Mailbox const from(rep_info_.rcpt_to_local_part, server_identity_);
//   Mailbox const to(rep_info_.mail_from);

//   std::string error_msg;
//   if (!send_.mail_from_rcpt_to(res_, from, to, error_msg)) {
//     out_() << error_msg << std::flush;
//     LOG(WARNING) << "failed to reply from <" << from << "> to <" << to << ">
//     "
//                  << error_msg;
//     return false;
//   }

//   LOG(INFO) << "RCPT TO:<" << rcpt_to << "> is a reply to "
//             << rep_info_.mail_from << " from " <<
//             rep_info_.rcpt_to_local_part;
//   return true;
// }

void Session::rcpt_to(Mailbox&& forward_path, parameters_t const& parameters)
{
  check_for_pipeline_error_("RCPT TO");

  switch (state_) {
  case xact_step::helo:
    out_() << "503 5.5.1 sequence error, expecting HELO/EHLO\r\n" << std::flush;
    LOG(WARNING) << "'RCPT TO' before HELO/EHLO"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::mail:
    out_() << "503 5.5.1 sequence error, expecting MAIL\r\n" << std::flush;
    LOG(WARNING) << "'RCPT TO' before 'MAIL FROM'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::rcpt:
  case xact_step::data: break;
  case xact_step::bdat:
    out_() << "503 5.5.1 sequence error, expecting BDAT\r\n" << std::flush;
    LOG(WARNING) << "'RCPT TO' during BDAT transfer"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  case xact_step::rset:
    out_() << "503 5.5.1 sequence error, expecting RSET\r\n" << std::flush;
    LOG(WARNING) << "error state must be cleared with a RSET"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return;
  }

  if (!verify_rcpt_params_(parameters))
    return;

  if (!verify_recipient_(forward_path))
    return;

  if (!smtputf8_ && !is_ascii(forward_path.local_part())) {
    LOG(WARNING) << "non ascii forward_path \"" << forward_path
                 << "\" without SMTPUTF8 paramater";
  }

  if (forward_path_.size() >= Config::max_recipients_per_message) {
    out_() << "452 4.5.3 too many recipients\r\n" << std::flush;
    LOG(WARNING) << "too many recipients <" << forward_path << ">";
    return;
  }
  // no check for dups, postfix doesn't
  forward_path_.emplace_back(std::move(forward_path));

  Mailbox const& rcpt_to_mbx = forward_path_.back();

  LOG(INFO) << "RCPT TO:<" << rcpt_to_mbx << ">";

  // auto const rcpt_to_str = rcpt_to_mbx.as_string();

  // if (auto reply = srs_.dec_reply(rcpt_to_mbx.local_part()); reply) {
  //   if (!reply_to_(*reply, rcpt_to_mbx))
  //     return;
  // }
  // else if (auto const forward = forward_.find(rcpt_to_str.c_str()); forward)
  // {
  //   if (!forward_to_(*forward, rcpt_to_mbx))
  //     return;
  // }
  // else {
  //   LOG(INFO) << "RCPT TO:<" << rcpt_to_str << ">";
  // }

  // No flush RFC-2920 section 3.1, this could be part of a command group.
  out_() << "250 2.1.5 RCPT TO OK\r\n";

  state_ = xact_step::data;
}

// The headers Received and Received-SPF are returned as a string.

std::string Session::added_headers_(MessageStore const& msg)
{
  auto const protocol{[this]() {
    if (sock_.tls() && !extensions_) {
      LOG(WARNING) << "TLS active without extensions";
    }
    // <https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml#mail-parameters-5>
    if (smtputf8_)
      return sock_.tls() ? "UTF8SMTPS" : "UTF8SMTP";
    else if (sock_.tls())
      return "ESMTPS";
    else if (extensions_)
      return "ESMTP";
    else
      return "SMTP";
  }()};

  fmt::memory_buffer headers;

  // Return-Path:
  fmt::format_to(headers, "Return-Path: <{}>\r\n", reverse_path_);

  // Received-SPF:
  if (!spf_received_.empty()) {
    fmt::format_to(headers, "{}\r\n", spf_received_);
  }

  // Received:
  // <https://tools.ietf.org/html/rfc5321#section-4.4>
  fmt::format_to(headers, "Received: from {}", client_identity_.utf8());
  if (sock_.has_peername()) {
    fmt::format_to(headers, " ({})", client_);
  }
  fmt::format_to(headers, "\r\n\tby {} with {} id {}", server_identity_.utf8(),
                 protocol, msg.id());
  if (forward_path_.size()) {
    fmt::format_to(headers, "\r\n\tfor <{}>", forward_path_[0]);
    for (auto i = 1u; i < forward_path_.size(); ++i)
      fmt::format_to(headers, ",\r\n\t   <{}>", forward_path_[i]);
  }
  std::string const tls_info{sock_.tls_info()};
  if (tls_info.length()) {
    fmt::format_to(headers, "\r\n\t({})", tls_info);
  }
  fmt::format_to(headers, ";\r\n\t{}\r\n", msg.when());

  return fmt::to_string(headers);
}

namespace {
bool lookup_domain(CDB& cdb, Domain const& domain)
{
  if (!domain.empty()) {
    if (cdb.contains(domain.ascii())) {
      return true;
    }
    if (domain.is_unicode() && cdb.contains(domain.utf8())) {
      return true;
    }
  }
  return false;
}
} // namespace

std::tuple<Session::SpamStatus, std::string> Session::spam_status_()
{
  if (spf_result_ == SPF::Result::FAIL && !ip_allowed_)
    return {SpamStatus::spam, "SPF failed"};

  // These should have already been rejected by verify_client_().
  if ((reverse_path_.domain() == "localhost.local") ||
      (reverse_path_.domain() == "localhost"))
    return {SpamStatus::spam, "bogus reverse_path"};

  std::vector<std::string> why_ham;

  // Anything enciphered tastes a lot like ham.
  if (sock_.tls())
    why_ham.emplace_back("they used TLS");

  if (spf_result_ == SPF::Result::PASS) {
    if (lookup_domain(allow_, spf_sender_domain_)) {
      why_ham.emplace_back(fmt::format("SPF sender domain ({}) is allowed",
                                       spf_sender_domain_.utf8()));
    }
    else {
      auto tld_dom{tld_db_.get_registered_domain(spf_sender_domain_.ascii())};
      if (tld_dom && allow_.contains(tld_dom)) {
        why_ham.emplace_back(fmt::format(
            "SPF sender registered domain ({}) is allowed", tld_dom));
      }
    }
  }

  if (fcrdns_allowed_)
    why_ham.emplace_back(
        fmt::format("FCrDNS (or it's registered domain) is allowed"));

  if (!why_ham.empty())
    return {SpamStatus::ham,
            fmt::format("{}", fmt::join(std::begin(why_ham), std::end(why_ham),
                                        ", and "))};

  return {SpamStatus::spam, "it's not ham"};
}

static std::string folder(Session::SpamStatus         status,
                          std::vector<Mailbox> const& forward_path,
                          Mailbox const&              reverse_path)
{
  if (status == Session::SpamStatus::spam)
    return ".Junk";

  return "";
}

bool Session::msg_new()
{
  CHECK((state_ == xact_step::data) || (state_ == xact_step::bdat));

  auto const& [status, reason]{spam_status_()};

  LOG(INFO) << ((status == SpamStatus::ham) ? "ham since " : "spam since ")
            << reason;

  // All sources of ham get a fresh 5 minute timeout per message.
  if (status == SpamStatus::ham) {
    if ((!FLAGS_immortal) && (getenv("GHSMTP_IMMORTAL") == nullptr))
      alarm(5 * 60);
  }

  msg_ = std::make_unique<MessageStore>();

  if (!FLAGS_max_write)
    FLAGS_max_write = max_msg_size();

  try {
    msg_->open(server_id_(), FLAGS_max_write,
               folder(status, forward_path_, reverse_path_));
    auto const hdrs{added_headers_(*(msg_.get()))};
    msg_->write(hdrs);

    // fmt::memory_buffer spam_status;
    // fmt::format_to(spam_status, "X-Spam-Status: {}, {}\r\n",
    //                ((status == SpamStatus::spam) ? "Yes" : "No"), reason);
    // msg_->write(spam_status.data(), spam_status.size());

    LOG(INFO) << "Spam-Status: "
              << ((status == SpamStatus::spam) ? "Yes" : "No") << ", "
              << reason;

    return true;
  }
  catch (std::system_error const& e) {
    switch (errno) {
    case ENOSPC:
      out_() << "452 4.3.1 insufficient system storage\r\n" << std::flush;
      LOG(ERROR) << "no space";
      msg_->trash();
      msg_.reset();
      return false;

    default:
      out_() << "451 4.0.0 mail system error\r\n" << std::flush;
      LOG(ERROR) << "errno==" << errno << ": " << strerror(errno);
      LOG(ERROR) << e.what();
      msg_->trash();
      msg_.reset();
      return false;
    }
  }
  catch (std::exception const& e) {
    out_() << "451 4.0.0 mail system error\r\n" << std::flush;
    LOG(ERROR) << e.what();
    msg_->trash();
    msg_.reset();
    return false;
  }

  out_() << "451 4.0.0 mail system error\r\n" << std::flush;
  LOG(ERROR) << "msg_new failed with no exception caught";
  msg_->trash();
  msg_.reset();
  return false;
}

bool Session::msg_write(char const* s, std::streamsize count)
{
  if ((state_ != xact_step::data) && (state_ != xact_step::bdat))
    return false;

  if (!msg_)
    return false;

  try {
    if (msg_->write(s, count))
      return true;
  }
  catch (std::system_error const& e) {
    switch (errno) {
    case ENOSPC:
      out_() << "452 4.3.1 insufficient system storage\r\n" << std::flush;
      LOG(ERROR) << "no space";
      msg_->trash();
      msg_.reset();
      return false;

    default:
      out_() << "451 4.0.0 mail system error\r\n" << std::flush;
      LOG(ERROR) << "errno==" << errno << ": " << strerror(errno);
      LOG(ERROR) << e.what();
      msg_->trash();
      msg_.reset();
      return false;
    }
  }
  catch (std::exception const& e) {
    out_() << "451 4.0.0 mail system error\r\n" << std::flush;
    LOG(ERROR) << e.what();
    msg_->trash();
    msg_.reset();
    return false;
  }

  out_() << "451 4.0.0 mail system error\r\n" << std::flush;
  LOG(ERROR) << "msg_write failed with no exception caught";
  msg_->trash();
  msg_.reset();
  return false;
}

bool Session::data_start()
{
  last_in_group_("DATA");

  switch (state_) {
  case xact_step::helo:
    out_() << "503 5.5.1 sequence error, expecting HELO/EHLO\r\n" << std::flush;
    LOG(WARNING) << "'DATA' before HELO/EHLO"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::mail:
    out_() << "503 5.5.1 sequence error, expecting MAIL\r\n" << std::flush;
    LOG(WARNING) << "'DATA' before 'MAIL FROM'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::rcpt:

    /******************************************************************
    <https://tools.ietf.org/html/rfc5321#section-3.3> says:

    The DATA command can fail at only two points in the protocol exchange:

    If there was no MAIL, or no RCPT, command, or all such commands were
    rejected, the server MAY return a "command out of sequence" (503) or
    "no valid recipients" (554) reply in response to the DATA command.

    However, <https://tools.ietf.org/html/rfc2033#section-4.2> says:

    The additional restriction is that when there have been no successful
    RCPT commands in the mail transaction, the DATA command MUST fail
    with a 503 reply code.

    Therefore I will send the reply code that is valid for both, and
    do the same for the BDAT case.
    *******************************************************************/

    out_() << "503 5.5.1 sequence error, expecting RCPT\r\n" << std::flush;
    LOG(WARNING) << "no valid recipients"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::data: break;
  case xact_step::bdat:
    out_() << "503 5.5.1 sequence error, expecting BDAT\r\n" << std::flush;
    LOG(WARNING) << "'DATA' during BDAT transfer"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::rset:
    out_() << "503 5.5.1 sequence error, expecting RSET\r\n" << std::flush;
    LOG(WARNING) << "error state must be cleared with a RSET"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  }

  if (binarymime_) {
    out_() << "503 5.5.1 sequence error, DATA does not support BINARYMIME\r\n"
           << std::flush;
    LOG(WARNING) << "DATA does not support BINARYMIME";
    state_ = xact_step::rset; // RFC 3030 section 3 page 5
    return false;
  }

  if (!msg_new()) {
    LOG(ERROR) << "msg_new() failed";
    return false;
  }

  out_() << "354 go, end with <CR><LF>.<CR><LF>\r\n" << std::flush;
  LOG(INFO) << "DATA";
  return true;
}

// bool Session::do_forward_(message::parsed& msg)
// {
//   auto msg_fwd = msg;

//   // Generate a reply address
//   Reply::from_to reply;
//   reply.mail_from          = msg_fwd.dmarc_from;
//   reply.rcpt_to_local_part = fwd_from_.local_part();

//   auto const reply_addr =
//       fmt::format("{}@{}", srs_.enc_reply(reply), server_id_());

//   auto const munging = false;

//   auto const sender   = server_identity_.ascii().c_str();
//   auto const selector = FLAGS_selector.c_str();
//   auto const key_file =
//       (config_path_ / FLAGS_selector).replace_extension("private");
//   CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

//   if (munging) {
//     auto const from_hdr =
//         fmt::format("From: \"{} via\" <@>", msg_fwd.dmarc_from, reply_addr);
//     message::rewrite_from_to(msg_fwd, from_hdr, "", sender, selector,
//     key_file);
//   }
//   else {
//     auto const reply_to_hdr = fmt::format("Reply-To: {}", reply_addr);
//     message::rewrite_from_to(msg_fwd, "", reply_to_hdr, sender, selector,
//                              key_file);
//   }

//   // Forward it on
//   if (!send_.send(msg_fwd.as_string())) {
//     out_() << "432 4.3.0 Recipient's incoming mail queue has been "
//               "stopped\r\n"
//            << std::flush;

//     LOG(ERROR) << "failed to send for " << fwd_path_;
//     return false;
//   }

//   LOG(INFO) << "successfully sent for " << fwd_path_;
//   return true;
// }

// bool Session::do_reply_(message::parsed& msg)
// {
//   Mailbox to_mbx(rep_info_.mail_from);
//   Mailbox from_mbx(rep_info_.rcpt_to_local_part, server_identity_);

//   auto reply = std::make_unique<MessageStore>();
//   reply->open(server_id_(), FLAGS_max_write, ".Drafts");

//   auto const date{Now{}};
//   auto const pill{Pill{}};
//   auto const mid_str =
//       fmt::format("<{}.{}@{}>", date.sec(), pill, server_identity_);

//   fmt::memory_buffer bfr;

//   fmt::format_to(bfr, "From: <{}>\r\n", from_mbx);
//   fmt::format_to(bfr, "To: <{}>\r\n", to_mbx);

//   fmt::format_to(bfr, "Date: {}\r\n", date.c_str());

//   fmt::format_to(bfr, "Message-ID: {}\r\n", mid_str.c_str());

//   if (!msg.get_header(message::Subject).empty()) {
//     fmt::format_to(bfr, "{}: {}\r\n", message::Subject,
//                    msg.get_header(message::Subject));
//   }
//   else {
//     fmt::format_to(bfr, "{}: {}\r\n", message::Subject,
//                    "Reply to your message");
//   }

//   if (!msg.get_header(message::In_Reply_To).empty()) {
//     fmt::format_to(bfr, "{}: {}\r\n", message::In_Reply_To,
//                    msg.get_header(message::In_Reply_To));
//   }

//   if (!msg.get_header(message::MIME_Version).empty() &&
//       msg.get_header(message::Content_Type).empty()) {
//     fmt::format_to(bfr, "{}: {}\r\n", message::MIME_Version,
//                    msg.get_header(message::MIME_Version));
//     fmt::format_to(bfr, "{}: {}\r\n", message::Content_Type,
//                    msg.get_header(message::Content_Type));
//   }

//   reply->write(fmt::to_string(bfr));

//   if (!msg.body.empty()) {
//     reply->write("\r\n");
//     reply->write(msg.body);
//   }

//   auto const      msg_data = reply->freeze();
//   message::parsed msg_reply;
//   CHECK(msg_reply.parse(msg_data));

//   auto const sender   = server_identity_.ascii().c_str();
//   auto const selector = FLAGS_selector.c_str();
//   auto const key_file =
//       (config_path_ / FLAGS_selector).replace_extension("private");
//   CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

//   message::dkim_sign(msg_reply, sender, selector, key_file);

//   if (!send_.send(msg_reply.as_string())) {
//     out_() << "432 4.3.0 Recipient's incoming mail queue has been "
//               "stopped\r\n"
//            << std::flush;

//     LOG(ERROR) << "send failed for reply to " << to_mbx << " from " <<
//     from_mbx; return false;
//   }

//   LOG(INFO) << "successful reply to " << to_mbx << " from " << from_mbx;
//   return true;
// }

bool Session::do_deliver_()
{
  CHECK(msg_);

  // auto const sender   = server_identity_.ascii().c_str();
  // auto const selector = FLAGS_selector.c_str();
  // auto const key_file =
  //     (config_path_ / FLAGS_selector).replace_extension("private");
  // CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

  try {
    // auto const msg_data = msg_->freeze();

    // message::parsed msg;

    // // Only deal in RFC-5322 Mail Objects.
    // bool const message_parsed = msg.parse(msg_data);
    // if (message_parsed) {

    //   // remove any Return-Path
    //   message::remove_delivery_headers(msg);

    //   auto const authentic =
    //       message_parsed &&
    //       message::authentication(msg, sender, selector, key_file);

    // // write a new Return-Path
    // msg_->write(fmt::format("Return-Path: <{}>\r\n", reverse_path_));

    //   for (auto const h : msg.headers) {
    //     msg_->write(h.as_string());
    //     msg_->write("\r\n");
    //   }
    //   if (!msg.body.empty()) {
    //     msg_->write("\r\n");
    //     msg_->write(msg.body);
    //   }

    msg_->deliver();

    // if (authentic && !fwd_path_.empty()) {
    //   if (!do_forward_(msg))
    //     return false;
    // }
    // if (authentic && !rep_info_.empty()) {
    //   if (!do_reply_(msg))
    //     return false;
    // }
    // }

    msg_->close();
  }
  catch (std::system_error const& e) {
    switch (errno) {
    case ENOSPC:
      out_() << "452 4.3.1 mail system full\r\n" << std::flush;
      LOG(ERROR) << "no space";
      msg_->trash();
      reset_();
      return false;

    default:
      out_() << "550 5.0.0 mail system error\r\n" << std::flush;
      if (errno)
        LOG(ERROR) << "errno==" << errno << ": " << strerror(errno);
      LOG(ERROR) << e.what();
      msg_->trash();
      reset_();
      return false;
    }
  }

  return true;
}

void Session::data_done()
{
  CHECK((state_ == xact_step::data));

  if (msg_ && msg_->size_error()) {
    data_size_error();
    return;
  }

  do_deliver_();

  // if (prdr_) {
  //   out_() << "353\r\n";
  //   for (auto fp : forward_path_) {
  //     out_() << "250 2.1.5 RCPT TO OK\r\n";
  //   }
  // }

  // Check for and act on magic "wait" address.
  {
    using namespace boost::xpressive;

    mark_tag     secs_(1);
    sregex const rex = icase("wait-data-") >> (secs_ = +_d);
    smatch       what;

    for (auto fp : forward_path_) {
      if (regex_match(fp.local_part(), what, rex)) {
        auto const str = what[secs_].str();
        LOG(INFO) << "waiting at DATA " << str << " seconds";
        long value = 0;
        std::from_chars(str.data(), str.data() + str.size(), value);
        sleep(value);
        LOG(INFO) << "done waiting";
      }
    }
  }

  out_() << "250 2.0.0 DATA OK\r\n" << std::flush;
  LOG(INFO) << "message delivered, " << msg_->size() << " octets, with id "
            << msg_->id();

  reset_();
}

void Session::data_size_error()
{
  out_().clear(); // clear possible eof from input side
  out_() << "552 5.3.4 message size limit exceeded\r\n" << std::flush;
  if (msg_) {
    msg_->trash();
  }
  LOG(WARNING) << "DATA size error";
  reset_();
}

void Session::data_error()
{
  out_().clear(); // clear possible eof from input side
  out_() << "554 5.3.0 message error of some kind\r\n" << std::flush;
  if (msg_) {
    msg_->trash();
  }
  LOG(WARNING) << "DATA error";
  reset_();
}

bool Session::bdat_start(size_t n)
{
  // In practice, this one gets pipelined.
  // last_in_group_("BDAT");

  switch (state_) {
  case xact_step::helo:
    out_() << "503 5.5.1 sequence error, expecting HELO/EHLO\r\n" << std::flush;
    LOG(WARNING) << "'BDAT' before HELO/EHLO"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::mail:
    out_() << "503 5.5.1 sequence error, expecting MAIL\r\n" << std::flush;
    LOG(WARNING) << "'BDAT' before 'MAIL FROM'"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::rcpt:
    // See comment in data_start()
    out_() << "503 5.5.1 sequence error, expecting RCPT\r\n" << std::flush;
    LOG(WARNING) << "no valid recipients"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  case xact_step::data: // first bdat
    break;
  case xact_step::bdat: return true;
  case xact_step::rset:
    out_() << "503 5.5.1 sequence error, expecting RSET\r\n" << std::flush;
    LOG(WARNING) << "error state must be cleared with a RSET"
                 << (sock_.has_peername() ? " from " : "") << client_;
    return false;
  }

  state_ = xact_step::bdat;

  return msg_new();
}

void Session::bdat_done(size_t n, bool last)
{
  if (state_ != xact_step::bdat) {
    bdat_seq_error();
    return;
  }

  if (!msg_) {
    return;
  }

  if (msg_->size_error()) {
    bdat_size_error();
    return;
  }

  if (!last) {
    out_() << "250 2.0.0 BDAT " << n << " OK\r\n" << std::flush;
    LOG(INFO) << "BDAT " << n;
    return;
  }

  do_deliver_();

  out_() << "250 2.0.0 BDAT " << n << " LAST OK\r\n" << std::flush;

  LOG(INFO) << "BDAT " << n << " LAST";
  LOG(INFO) << "message delivered, " << msg_->size() << " octets, with id "
            << msg_->id();
  reset_();
}

void Session::bdat_size_error()
{
  out_().clear(); // clear possible eof from input side
  out_() << "552 5.3.4 message size limit exceeded\r\n" << std::flush;
  if (msg_) {
    msg_->trash();
  }
  LOG(WARNING) << "BDAT size error";
  reset_();
}

void Session::bdat_seq_error()
{
  out_().clear(); // clear possible eof from input side
  out_() << "503 5.5.1 BDAT sequence error\r\n" << std::flush;
  if (msg_) {
    msg_->trash();
  }
  LOG(WARNING) << "BDAT sequence error";
  reset_();
}

void Session::bdat_io_error()
{
  out_().clear(); // clear possible eof from input side
  out_() << "503 5.5.1 BDAT I/O error\r\n" << std::flush;
  if (msg_) {
    msg_->trash();
  }
  LOG(WARNING) << "BDAT I/O error";
  reset_();
}

void Session::rset()
{
  out_() << "250 2.1.5 RSET OK\r\n";
  // No flush RFC-2920 section 3.1, this could be part of a command group.
  LOG(INFO) << "RSET";
  reset_();
}

void Session::noop(std::string_view str)
{
  last_in_group_("NOOP");
  out_() << "250 2.0.0 NOOP OK\r\n" << std::flush;
  LOG(INFO) << "NOOP" << (str.length() ? " " : "") << str;
}

void Session::vrfy(std::string_view str)
{
  last_in_group_("VRFY");
  out_() << "252 2.1.5 try it\r\n" << std::flush;
  LOG(INFO) << "VRFY" << (str.length() ? " " : "") << str;
}

void Session::help(std::string_view str)
{
  out_() << "214 2.0.0 see https://digilicious.com/smtp.html\r\n" << std::flush;
  LOG(INFO) << "HELP" << (str.length() ? " " : "") << str;
}

void Session::quit()
{
  // send_.quit();
  // last_in_group_("QUIT");
  out_() << "221 2.0.0 closing connection\r\n" << std::flush;
  LOG(INFO) << "QUIT";
  exit_();
}

void Session::auth()
{
  out_() << "454 4.7.0 authentication failure\r\n" << std::flush;
  LOG(INFO) << "AUTH";
  bad_host_("auth");
}

void Session::error(std::string_view log_msg)
{
  out_() << "421 4.3.5 system error: " << log_msg << "\r\n" << std::flush;
  LOG(WARNING) << log_msg;
}

void Session::cmd_unrecognized(std::string_view cmd)
{
  auto const escaped{esc(cmd)};
  LOG(WARNING) << "command unrecognized: \"" << escaped << "\"";

  if (++n_unrecognized_cmds_ >= Config::max_unrecognized_cmds) {
    out_() << "500 5.5.1 command unrecognized: \"" << escaped
           << "\" exceeds limit\r\n"
           << std::flush;
    LOG(WARNING) << n_unrecognized_cmds_
                 << " unrecognized commands is too many";
    exit_();
  }

  out_() << "500 5.5.1 command unrecognized: \"" << escaped << "\"\r\n"
         << std::flush;
}

void Session::bare_lf()
{
  // Error code used by Office 365.
  out_() << "554 5.6.11 bare LF\r\n" << std::flush;
  LOG(WARNING) << "bare LF";
  exit_();
}

void Session::max_out()
{
  out_() << "552 5.3.4 message size limit exceeded\r\n" << std::flush;
  LOG(WARNING) << "message size maxed out";
  exit_();
}

void Session::time_out()
{
  out_() << "421 4.4.2 time-out\r\n" << std::flush;
  LOG(WARNING) << "time-out" << (sock_.has_peername() ? " from " : "")
               << client_;
  exit_();
}

void Session::starttls()
{
  last_in_group_("STARTTLS");
  if (sock_.tls()) {
    out_() << "554 5.5.1 TLS already active\r\n" << std::flush;
    LOG(WARNING) << "STARTTLS issued with TLS already active";
  }
  else if (!extensions_) {
    out_() << "554 5.5.1 TLS not avaliable without using EHLO\r\n"
           << std::flush;
    LOG(WARNING) << "STARTTLS issued without using EHLO";
  }
  else {
    out_() << "220 2.0.0 STARTTLS OK\r\n" << std::flush;
    if (sock_.starttls_server(config_path_)) {
      reset_();
      max_msg_size(Config::max_msg_size_bro);
      LOG(INFO) << "STARTTLS " << sock_.tls_info();
    }
    else {
      LOG(INFO) << "failed STARTTLS";
    }
  }
}

void Session::exit_()
{
  // sock_.log_totals();

  timespec time_used{};
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_used);

  LOG(INFO) << "CPU time " << time_used.tv_sec << "." << std::setw(9)
            << std::setfill('0') << time_used.tv_nsec << " seconds";

  std::exit(EXIT_SUCCESS);
}

namespace {
bool ip4_allowed(char const* addr)
{
  struct nw {
    char const* net;
    char const* mask;
    char const* comment;
  };

  // clang-format off

  // 255 0b11111111 8
  // 254 0b11111110 7
  // 252 0b11111100 6
  // 248 0b11111000 5
  // 240 0b11110000 4
  // 224 0b11100000 3
  // 192 0b11000000 2
  // 128 0b10000000 1

  nw const networks[]{
    // the one very special case
    {"108.83.36.112",   "255.255.255.248", "108.83.36.112/29"},

    // accept from major providers:
    {"3.0.0.0",         "255.0.0.0",       "3.0.0.0/9 and 3.128.0.0/9 Amazon"},
    {"5.45.198.0",      "255.255.254.0",   "5.45.198.0/23 YANDEX-5-45-198"},
    {"12.153.224.0",    "255.255.255.0",   "12.153.224.0/24 E-TRADE10-224"},
    {"13.108.0.0",      "255.252.0.0",     "13.108.0.0/14 SALESF-3 NET-13-108-0-0-1"},
    {"17.0.0.0",        "255.0.0.0",       "17.0.0.0/8 APPLE-WWNET"},
    {"20.67.221.0",     "255.255.255.0",   "20.64.0.0/10 NET-20-33-0-0-1 duck.com"},
    {"20.67.222.0",     "255.255.255.0",   "20.64.0.0/10 NET-20-33-0-0-1 duck.com"},
    {"20.67.223.0",     "255.255.255.0",   "20.64.0.0/10 NET-20-33-0-0-1 duck.com"},
    {"40.74.0.0",       "255.254.0.0",     "40.74.0.0/15 MSFT NET-40-74-0-0-1"},
    {"40.76.0.0",       "255.252.0.0",     "40.76.0.0/14 MSFT NET-40-74-0-0-1"},
    {"40.80.0.0",       "255.240.0.0",     "40.80.0.0/12 MSFT NET-40-74-0-0-1"},
    {"40.92.0.0",       "255.252.0.0",     "40.96.0.0/14 MSFT NET-40-74-0-0-1"},
    {"40.96.0.0",       "255.240.0.0",     "40.96.0.0/12 MSFT NET-40-74-0-0-1"},
    {"40.112.0.0",      "255.248.0.0",     "40.112.0.0/13 MSFT NET-40-74-0-0-1"},
    {"40.120.0.0",      "255.252.0.0",     "40.120.0.0/14 MSFT NET-40-74-0-0-1"},
    {"40.124.0.0",      "255.255.0.0",     "40.124.0.0/16 MSFT NET-40-74-0-0-1"},
    {"40.125.0.0",      "255.255.128.0",   "40.125.0.0/17 MSFT NET-40-74-0-0-1"},
    {"56.0.0.0",        "255.0.0.0",       "56.0.0.0/8 USPS1"},
    {"65.52.0.0",       "255.252.0.0",     "65.52.0.0/14 MICROSOFT-1BLK"},
    {"65.196.177.0",    "255.255.255.0",   "UU-65-196-177 E*TRADE FINANCIAL CORPORATION (C05251409)"},
    {"66.163.160.0",    "255.255.224.0",   "66.163.160.0/19 A-YAHOO-US2"},
    {"66.211.176.0",    "255.255.240.0",   "66.211.176.0/20 EBAY-2"},
    {"66.211.172.0",    "255.255.252.0",   "66.211.172.0/22 EBAY-2"},
    {"66.220.144.0",    "255.255.240.0",   "66.220.144.0/20 TFBNET3"},
    {"68.232.192.0",    "255.255.240.0",   "68.232.192.0/20 EXACT-IP-NET-2"},
    {"69.171.224.0",    "255.255.224.0",   "69.171.224.0/19 TFBNET3"},
    {"70.47.67.0",      "255.255.255.0",   "70.47.67.0/24 NET-462F4300-24"},
    {"74.6.0.0",        "255.255.0.0",     "INKTOMI-BLK-6 Oath"},
    {"74.125.0.0",      "255.255.0.0",     "74.125.0.0/16 GOOGLE"},
    {"75.101.100.43",   "255.255.255.255", "new.toad.com"},
    {"76.178.68.57",    "255.255.255.255", "cpe-76-178-68-57.natsow.res.rr.com"},
    {"98.136.0.0",      "255.252.0.0",     "98.136.0.0/14 A-YAHOO-US9"},
    {"104.40.0.0",      "255.248.0.0",     "104.40.0.0/13 MSFT"},
    {"108.174.0.0",     "255.255.240.0",   "108.174.0.0/20 LINKEDIN"},
    {"159.45.0.0",      "255.255.0.0",     "159.45.0.0/16 AGE-COM"},
    {"159.53.0.0",      "255.255.0.0",     "159.53.0.0/16 JMC"},
    {"159.135.224.0",   "255.255.240.0",   "159.135.224.0/20 MNO87-159-135-224-0-0"},
    {"162.247.72.0",    "255.255.252.0",   "162.247.72.0/22 CALYX-INSTITUTE-V4-1"},
    {"165.107.0.0",     "255.255.0.0",     "NET-LDC-CA-GOV"},
    {"192.175.128.0",   "255.255.128.0",   "192.175.128.0/17 NETBLK-VANGUARD"},
    {"198.2.128.0",     "255.255.192.0",   "198.2.128.0/18 RSG-DELIVERY"},
    {"198.252.206.0",   "255.255.255.0",   "198.252.206.0/24 SE-NET01"},
    {"199.122.120.0",   "255.255.248.0",   "199.122.120.0/21 EXACT-IP-NET-3"},
    {"204.13.164.0",    "255.255.255.0",   "204.13.164.0/24 RISEUP-NETWORKS-SWIFT-BLOCK2"},
    {"204.29.186.0",    "255.255.254.0",   "204.29.186.0/23 ATDN-NSCAPE"},
    {"205.139.104.0",   "255.255.252.0",   "205.139.104.0/22 SAVV-S259964-8"},
    {"205.201.128.0",   "255.255.240.0",   "205.201.128.0/20 RSG-DELIVERY"},
    {"208.118.235.0",   "255.255.255.0",   "208.118.235.0/24 TWDX-208-118-235-0-1"},
    {"208.192.0.0",     "255.192.0.0",     "208.192.0.0/10 UUNET1996B"},
    {"209.51.188.0",    "255.255.255.0",   "I:NET-209.51.188.0/24 FSF"},
    {"209.85.128.0",    "255.255.128.0",   "209.85.128.0/17 GOOGLE"},
    {"209.132.176.0",   "255.255.240.0",   "209.132.176.0/20 RED-HAT-BLK"},
    {"209.237.224.0",   "255.255.224.0",   "UNITEDLAYER-1"},
//  {"209.237.225.253", "255.255.255.255", "Old new.toad.com"},
  };
  // clang-format on

  uint32_t addr32;
  CHECK_EQ(inet_pton(AF_INET, addr, &addr32), 1)
      << "can't interpret as IPv4 address";

  for (auto const& network : networks) {
    uint32_t net32;
    CHECK_EQ(inet_pton(AF_INET, network.net, &net32), 1)
        << "can't grok " << network.net;
    uint32_t mask32;
    CHECK_EQ(inet_pton(AF_INET, network.mask, &mask32), 1)
        << "can't grok " << network.mask;

    // sanity check: all unmasked bits must be zero
    CHECK_EQ(net32 & (~mask32), 0)
        << "bogus config net=" << network.net << ", mask=" << network.mask;

    if (net32 == (addr32 & mask32)) {
      LOG(INFO) << addr << " allowed " << network.comment;
      return true;
    }
  }

  return false;
}
} // namespace

/////////////////////////////////////////////////////////////////////////////

// All of the verify_* functions send their own error messages back to
// the client on failure, and return false.

bool Session::verify_ip_address_(std::string& error_msg)
{
  auto ip_block_db_name = config_path_ / "ip-block";
  CDB  ip_block;
  if (ip_block.open(ip_block_db_name) &&
      ip_block.contains(sock_.them_c_str())) {
    error_msg =
        fmt::format("IP address {} on static blocklist", sock_.them_c_str());
    out_() << "554 5.7.1 " << error_msg << "\r\n" << std::flush;
    return false;
  }

  client_fcrdns_.clear();

  if ((sock_.them_address_literal() == IP4::loopback_literal) ||
      (sock_.them_address_literal() == IP6::loopback_literal)) {
    LOG(INFO) << "loopback address allowed";
    ip_allowed_ = true;
    client_fcrdns_.emplace_back("localhost");
    client_ = fmt::format("localhost {}", sock_.them_address_literal());
    return true;
  }

  if (IP::is_private(sock_.them_address_literal())) {
    LOG(INFO) << "local address allowed";
    ip_allowed_ = true;
    client_     = sock_.them_address_literal();
    return true;
  }

  auto const fcrdns = DNS::fcrdns(res_, sock_.them_c_str());
  for (auto const& fcr : fcrdns) {
    client_fcrdns_.emplace_back(fcr);
  }

  if (!client_fcrdns_.empty()) {
    client_ = fmt::format("{} {}", client_fcrdns_.front().ascii(),
                          sock_.them_address_literal());
    // check allow list
    for (auto const& client_fcrdns : client_fcrdns_) {
      if (allow_.contains(client_fcrdns.ascii())) {
        // LOG(INFO) << "FCrDNS " << client_fcrdns << " allowed";
        fcrdns_allowed_ = true;
        return true;
      }
      auto const tld{tld_db_.get_registered_domain(client_fcrdns.ascii())};
      if (tld) {
        if (allow_.contains(tld)) {
          // LOG(INFO) << "FCrDNS registered domain " << tld << " allowed";
          fcrdns_allowed_ = true;
          return true;
        }
      }
    }
    // check blocklist
    for (auto const& client_fcrdns : client_fcrdns_) {
      if (block_.contains(client_fcrdns.ascii())) {
        error_msg =
            fmt::format("FCrDNS {} on static blocklist", client_fcrdns.ascii());
        out_() << "554 5.7.1 blocklisted\r\n" << std::flush;
        return false;
      }

      auto const tld{tld_db_.get_registered_domain(client_fcrdns.ascii())};
      if (tld) {
        if (block_.contains(tld)) {
          error_msg = fmt::format(
              "FCrDNS registered domain {} on static blocklist", tld);
          out_() << "554 5.7.1 blocklisted\r\n" << std::flush;
          return false;
        }
      }
    }
  }
  else {
    client_ = fmt::format("{}", sock_.them_address_literal());
  }

  if (IP4::is_address(sock_.them_c_str())) {

    if (ip4_allowed(sock_.them_c_str())) {
      LOG(INFO) << "on internal allow list";
      ip_allowed_ = true;
      return true;
    }

    auto const reversed{IP4::reverse(sock_.them_c_str())};

    /*
    // Check with allow list.
    std::shuffle(std::begin(Config::wls), std::end(Config::wls),
                 random_device_);

    for (auto wl : Config::wls) {
      DNS::Query q(res_, DNS::RR_type::A, reversed + wl);
      if (q.has_record()) {
        using namespace boost::xpressive;

        auto const as = q.get_strings()[0];
        LOG(INFO) << "on allow list " << wl << " as " << as;

        mark_tag     x_(1);
        mark_tag     y_(2);
        sregex const rex = as_xpr("127.0.") >> (x_ = +_d) >> '.' >> (y_ = +_d);
        smatch       what;

        if (regex_match(as, what, rex)) {
          auto const x = what[x_].str();
          auto const y = what[y_].str();

          int value = 0;
          std::from_chars(y.data(), y.data() + y.size(), value);
          if (value > 0) {
            ip_allowed_ = true;
            LOG(INFO) << "allowed";
          }
        }

        // Any A record skips check on block list
        return true;
      }
    }
    */

    // Check with block lists. <https://en.wikipedia.org/wiki/DNSBL>
    std::shuffle(std::begin(Config::bls), std::end(Config::bls),
                 random_device_);

    for (auto bl : Config::bls) {

      DNS::Query q(res_, DNS::RR_type::A, reversed + bl);
      if (q.has_record()) {
        auto const as = q.get_strings()[0];
        if (as == "127.0.1.1") {
          LOG(INFO) << "Query blocked by " << bl;
        }
        else {
          error_msg = fmt::format("blocked on advice from {}", bl);
          LOG(INFO) << sock_.them_c_str() << " " << error_msg;
          out_() << "554 5.7.1 " << error_msg << "\r\n" << std::flush;
          return false;
        }
      }
    }
    // LOG(INFO) << "IP address " << sock_.them_c_str() << " cleared by dnsbls";
  }

  return true;
}

// check the identity from HELO/EHLO
bool Session::verify_client_(Domain const& client_identity,
                             std::string&  error_msg)
{
  if (!client_fcrdns_.empty()) {
    if (auto id = std::find(begin(client_fcrdns_), end(client_fcrdns_),
                            client_identity);
        id != end(client_fcrdns_)) {
      // If the HELO ident is one of the FCrDNS names...
      if (id != begin(client_fcrdns_)) {
        // ...then rotate that one to the front of the list
        std::rotate(begin(client_fcrdns_), id, id + 1);
      }
      client_ = fmt::format("{} {}", client_fcrdns_.front().ascii(),
                            sock_.them_address_literal());
      return true;
    }
    LOG(INFO) << "claimed identity " << client_identity
              << " does NOT match any FCrDNS: ";
    for (auto const& client_fcrdns : client_fcrdns_) {
      LOG(INFO) << "                 " << client_fcrdns;
    }
  }

  // Bogus clients claim to be us or some local host.
  if (sock_.has_peername() && ((client_identity == server_identity_) ||
                               (client_identity == "localhost") ||
                               (client_identity == "localhost.localdomain"))) {

    if ((sock_.them_address_literal() == IP4::loopback_literal) ||
        (sock_.them_address_literal() == IP6::loopback_literal)) {
      return true;
    }

    // Give 'em a pass.
    if (ip_allowed_) {
      LOG(INFO) << "allow-listed IP address can claim to be "
                << client_identity;
      return true;
    }

    // Ease up in test mode.
    if (FLAGS_test_mode || getenv("GHSMTP_TEST_MODE")) {
      return true;
    }

    error_msg = fmt::format("liar, claimed to be {}", client_identity.ascii());
    out_() << "550 5.7.1 liar\r\n" << std::flush;
    return false;
  }

  std::vector<std::string> labels;
  boost::algorithm::split(labels, client_identity.ascii(),
                          boost::algorithm::is_any_of("."));
  if (labels.size() < 2) {
    error_msg =
        fmt::format("claimed bogus identity {}", client_identity.ascii());
    out_() << "550 4.7.1 bogus identity\r\n" << std::flush;
    return false;
    // // Sometimes we may want to look at mail from non conforming
    // // sending systems.
    // LOG(WARNING) << "invalid sender" << (sock_.has_peername() ? " " : "")
    //              << client_ << " claiming " << client_identity;
    // return true;
  }

  if (lookup_domain(block_, client_identity)) {
    error_msg =
        fmt::format("claimed blocked identity {}", client_identity.ascii());
    out_() << "550 4.7.1 blocked identity\r\n" << std::flush;
    return false;
  }

  auto const tld{tld_db_.get_registered_domain(client_identity.ascii())};
  if (!tld) {
    // Sometimes we may want to look at mail from misconfigured
    // sending systems.
    // LOG(WARNING) << "claimed identity has no registered domain";
    // return true;
  }
  else if (block_.contains(tld)) {
    error_msg =
        fmt::format("claimed identity has blocked registered domain {}", tld);
    out_() << "550 4.7.1 blocked registered domain\r\n" << std::flush;
    return false;
  }

  // not otherwise objectionable
  return true;
}

// check sender from RFC5321 MAIL FROM:
bool Session::verify_sender_(Mailbox const& sender, std::string& error_msg)
{
  std::string const sender_str{sender};

  auto bad_senders_db_name = config_path_ / "bad_senders";
  CDB  bad_senders;
  if (bad_senders.open(bad_senders_db_name) &&
      bad_senders.contains(sender_str)) {
    error_msg = fmt::format("{} bad sender", sender_str);
    out_() << "550 5.1.8 " << error_msg << "\r\n" << std::flush;
    return false;
  }

  // We don't accept mail /from/ a domain we are expecting to accept
  // mail for on an external network connection.

  if (sock_.them_address_literal() != sock_.us_address_literal()) {
    if ((accept_domains_.is_open() &&
         (accept_domains_.contains(sender.domain().ascii()) ||
          accept_domains_.contains(sender.domain().utf8()))) ||
        (sender.domain() == server_identity_)) {

      // Ease up in test mode.
      if (FLAGS_test_mode || getenv("GHSMTP_TEST_MODE")) {
        return true;
      }
      out_() << "550 5.7.1 liar\r\n" << std::flush;
      error_msg = fmt::format("liar, claimed to be {}", sender.domain());
      return false;
    }
  }

  if (sender.domain().is_address_literal()) {
    if (sender.domain() != sock_.them_address_literal()) {
      LOG(WARNING) << "sender domain " << sender.domain() << " does not match "
                   << sock_.them_address_literal();
    }
    return true;
  }

  if (!verify_sender_spf_(sender)) {
    error_msg = "failed SPF check";
    return false;
  }

  if (!verify_sender_domain_(sender.domain(), error_msg)) {
    return false;
  }

  return true;
}

// this sender is the RFC5321 MAIL FROM: domain part
bool Session::verify_sender_domain_(Domain const& sender,
                                    std::string&  error_msg)
{
  if (sender.empty()) {
    // MAIL FROM:<>
    // is used to send bounce messages.
    return true;
  }

  // Break sender domain into labels:

  std::vector<std::string> labels;
  boost::algorithm::split(labels, sender.ascii(),
                          boost::algorithm::is_any_of("."));

  if (labels.size() < 2) { // This is not a valid domain.
    error_msg = fmt::format("{} invalid syntax", sender.ascii());
    out_() << "550 5.7.1 " << error_msg << "\r\n" << std::flush;
    return false;
  }

  if (allow_.contains(sender.ascii())) {
    LOG(INFO) << "sender " << sender.ascii() << " allowed";
    return true;
  }
  auto const reg_dom{tld_db_.get_registered_domain(sender.ascii())};
  if (reg_dom) {
    if (allow_.contains(reg_dom)) {
      LOG(INFO) << "sender registered domain \"" << reg_dom << "\" allowed";
      return true;
    }

    // LOG(INFO) << "looking up " << reg_dom;
    return verify_sender_domain_uribl_(reg_dom, error_msg);
  }

  LOG(INFO) << "sender \"" << sender << "\" not disallowed";
  return true;
}

// check sender domain on dynamic URI block lists
bool Session::verify_sender_domain_uribl_(std::string_view sender,
                                          std::string&     error_msg)
{
  if (!sock_.has_peername()) // short circuit
    return true;

  std::shuffle(std::begin(Config::uribls), std::end(Config::uribls),
               random_device_);
  for (auto uribl : Config::uribls) {
    auto const lookup = fmt::format("{}.{}", sender, uribl);
    auto       as     = DNS::get_strings(res_, DNS::RR_type::A, lookup);
    if (!as.empty()) {
      if (as.front() == "127.0.0.1")
        continue;
      error_msg = fmt::format("{} blocked on advice of {}", sender, uribl);
      out_() << "550 5.7.1 sender " << error_msg << "\r\n" << std::flush;
      return false;
    }
  }

  LOG(INFO) << "sender \"" << sender << "\" not blocked by URIBLs";
  return true;
}

bool Session::verify_sender_spf_(Mailbox const& sender)
{
  if (!sock_.has_peername()) {
    auto const ip_addr = "127.0.0.1"; // use localhost for local socket
    spf_received_ =
        fmt::format("Received-SPF: pass ({}: allow-listed) client-ip={}; "
                    "envelope-from={}; helo={};",
                    server_id_(), ip_addr, sender, client_identity_);
    spf_sender_domain_ = "localhost";
    return true;
  }

  auto const spf_srv     = SPF::Server{server_id_().c_str()};
  auto       spf_request = SPF::Request{spf_srv};

  if (IP4::is_address(sock_.them_c_str())) {
    spf_request.set_ipv4_str(sock_.them_c_str());
  }
  else if (IP6::is_address(sock_.them_c_str())) {
    spf_request.set_ipv6_str(sock_.them_c_str());
  }
  else {
    LOG(FATAL) << "bogus address " << sock_.them_address_literal() << ", "
               << sock_.them_c_str();
  }

  auto const from{static_cast<std::string>(sender)};

  spf_request.set_env_from(from.c_str());
  spf_request.set_helo_dom(client_identity_.ascii().c_str());

  auto const spf_res{SPF::Response{spf_request}};
  spf_result_        = spf_res.result();
  spf_received_      = spf_res.received_spf();
  spf_sender_domain_ = spf_request.get_sender_dom();

  LOG(INFO) << "spf_received_ == " << spf_received_;

  if (spf_result_ == SPF::Result::FAIL) {
    LOG(WARNING) << spf_res.header_comment();
  }
  else {
    LOG(INFO) << spf_res.header_comment();
  }

  if (spf_result_ == SPF::Result::PASS) {
    if (lookup_domain(block_, spf_sender_domain_)) {
      LOG(INFO) << "SPF sender domain (" << spf_sender_domain_
                << ") is blocked";
      return false;
    }
  }

  return true;
}

bool Session::verify_from_params_(parameters_t const& parameters)
{
  // Take a look at the optional parameters:
  for (auto const& [name, value] : parameters) {
    if (iequal(name, "BODY")) {
      if (iequal(value, "8BITMIME")) {
        // everything is cool, this is our default...
      }
      else if (iequal(value, "7BIT")) {
        // nothing to see here, move along...
      }
      else if (iequal(value, "BINARYMIME")) {
        binarymime_ = true;
      }
      else {
        LOG(WARNING) << "unrecognized BODY type \"" << value << "\" requested";
      }
    }
    else if (iequal(name, "SMTPUTF8")) {
      if (!value.empty()) {
        LOG(WARNING) << "SMTPUTF8 parameter has a value: " << value;
      }
      smtputf8_ = true;
    }

    // else if (iequal(name, "PRDR")) {
    //   LOG(INFO) << "using PRDR";
    //   prdr_ = true;
    // }

    else if (iequal(name, "SIZE")) {
      if (value.empty()) {
        LOG(WARNING) << "SIZE parameter has no value.";
      }
      else {
        try {
          auto const sz = stoull(value);
          if (sz > max_msg_size()) {
            out_() << "552 5.3.4 message size limit exceeded\r\n" << std::flush;
            LOG(WARNING) << "SIZE parameter too large: " << sz;
            return false;
          }
        }
        catch (std::invalid_argument const& e) {
          LOG(WARNING) << "SIZE parameter has invalid value: " << value;
        }
        catch (std::out_of_range const& e) {
          LOG(WARNING) << "SIZE parameter has out-of-range value: " << value;
        }
        // I guess we just ignore bad size parameters.
      }
    }
    else if (iequal(name, "REQUIRETLS")) {
      if (!sock_.tls()) {
        out_() << "554 5.7.1 REQUIRETLS needed\r\n" << std::flush;
        LOG(WARNING) << "REQUIRETLS needed";
        return false;
      }
    }
    else {
      LOG(WARNING) << "unrecognized 'MAIL FROM' parameter " << name << "="
                   << value;
    }
  }

  return true;
}

bool Session::verify_rcpt_params_(parameters_t const& parameters)
{
  // Take a look at the optional parameters:
  for (auto const& [name, value] : parameters) {
    if (iequal(name, "RRVS")) {
      // rrvs-param = "RRVS=" date-time [ ";" ( "C" / "R" ) ]
      LOG(INFO) << name << "=" << value;
    }
    else {
      LOG(WARNING) << "unrecognized 'RCPT TO' parameter " << name << "="
                   << value;
    }
  }

  return true;
}

// check recipient from RFC5321 RCPT TO:
bool Session::verify_recipient_(Mailbox const& recipient)
{
  if ((recipient.local_part() == "Postmaster") && (recipient.domain() == "")) {
    LOG(INFO) << "magic Postmaster address";
    return true;
  }

  auto const accepted_domain{[this, &recipient] {
    if (recipient.domain().is_address_literal()) {
      if (recipient.domain() != sock_.us_address_literal()) {
        LOG(WARNING) << "recipient.domain address " << recipient.domain()
                     << " does not match ours " << sock_.us_address_literal();
        return false;
      }
      return true;
    }

    // Domains we accept mail for.
    if (accept_domains_.is_open()) {
      if (accept_domains_.contains(recipient.domain().ascii()) ||
          accept_domains_.contains(recipient.domain().utf8())) {
        return true;
      }
    }
    else {
      // If we have no list of domains to accept, at least take our own.
      if (recipient.domain() == server_id_()) {
        return true;
      }
    }

    return false;
  }()};

  if (!accepted_domain) {
    out_() << "554 5.7.1 relay access denied\r\n" << std::flush;
    LOG(WARNING) << "relay access denied for domain " << recipient.domain();
    return false;
  }

  // Check for local addresses we reject.
  {
    auto bad_recipients_db_name = config_path_ / "bad_recipients";
    CDB  bad_recipients_db;
    if (bad_recipients_db.open(bad_recipients_db_name) &&
        bad_recipients_db.contains(recipient.local_part())) {
      out_() << "550 5.1.1 bad recipient " << recipient << "\r\n" << std::flush;
      LOG(WARNING) << "bad recipient " << recipient;
      return false;
    }
  }

  {
    auto temp_fail_db_name = config_path_ / "temp_fail";
    CDB  temp_fail; // Addresses we make wait...
    if (temp_fail.open(temp_fail_db_name) &&
        temp_fail.contains(recipient.local_part())) {
      out_() << "432 4.3.0 Recipient's incoming mail queue has been stopped\r\n"
             << std::flush;
      LOG(WARNING) << "temp fail for recipient " << recipient;
      return false;
    }
  }

  // Check for and act on magic "wait" address.
  {
    using namespace boost::xpressive;

    mark_tag     secs_(1);
    sregex const rex = icase("wait-rcpt-") >> (secs_ = +_d);
    smatch       what;

    if (regex_match(recipient.local_part(), what, rex)) {
      auto const str = what[secs_].str();
      LOG(INFO) << "waiting at RCPT TO " << str << " seconds";
      long value = 0;
      std::from_chars(str.data(), str.data() + str.size(), value);
      sleep(value);
      LOG(INFO) << "done waiting";
    }
  }

  // This is a trap for a probe done by some senders to see if we
  // accept just any old local-part.
  if (!extensions_) {
    if (recipient.local_part().length() > 8) {
      out_() << "550 5.1.1 unknown recipient " << recipient << "\r\n"
             << std::flush;
      LOG(WARNING) << "unknown recipient for HELO " << recipient;
      return false;
    }
  }

  return true;
}

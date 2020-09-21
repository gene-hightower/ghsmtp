#ifndef SESSION_DOT_HPP
#define SESSION_DOT_HPP

#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "CDB.hpp"
#include "DNS-fcrdns.hpp"
#include "Domain.hpp"
#include "Mailbox.hpp"
#include "MessageStore.hpp"
#include "SPF.hpp"
#include "SRS0.hpp"
#include "Send.hpp"
#include "Sock.hpp"
#include "TLD.hpp"
#include "message.hpp"

namespace Config {
constexpr size_t kibibyte             = 1024;
constexpr size_t mebibyte             = kibibyte * kibibyte;
constexpr size_t max_msg_size_initial = 15 * mebibyte;
constexpr size_t max_msg_size_bro     = 150 * mebibyte;
} // namespace Config

class Session {
public:
  using parameters_t = std::unordered_map<std::string, std::string>;

  Session(Session const&) = delete;
  Session& operator=(Session const&) = delete;

  explicit Session(
      fs::path                  config_path,
      std::function<void(void)> read_hook = []() {},
      int                       fd_in     = STDIN_FILENO,
      int                       fd_out    = STDOUT_FILENO);

  void greeting();
  void ehlo(std::string_view client_identity) { lo_("EHLO", client_identity); }
  void helo(std::string_view client_identity) { lo_("HELO", client_identity); }
  void mail_from(Mailbox&& reverse_path, parameters_t const& parameters);
  void rcpt_to(Mailbox&& forward_path, parameters_t const& parameters);

  bool msg_new();
  bool msg_write(char const* s, std::streamsize count);

  bool data_start();
  void data_done();
  void data_size_error();
  void data_error();

  bool bdat_start(size_t n);
  void bdat_done(size_t n, bool last);
  void bdat_size_error();
  void bdat_seq_error();
  void bdat_io_error();

  void rset();
  void noop(std::string_view str);
  void vrfy(std::string_view str);
  void help(std::string_view str);
  void quit() __attribute__((noreturn));
  void auth() __attribute__((noreturn));
  void error(std::string_view log_msg);
  void cmd_unrecognized(std::string_view log_msg);
  void bare_lf() __attribute__((noreturn));

  void max_out() __attribute__((noreturn));
  void time_out() __attribute__((noreturn));
  void starttls();

  bool          maxed_out() { return sock_.maxed_out(); }
  bool          timed_out() { return sock_.timed_out(); }
  std::istream& in() { return sock_.in(); }

  void flush();
  void last_in_group_(std::string_view verb);

  size_t max_msg_size() const { return max_msg_size_; }
  void   max_msg_size(size_t max);

  void log_stats() { sock_.log_stats(); }

  enum class SpamStatus : bool { ham, spam };

private:
  friend struct Session_test;

  std::tuple<SpamStatus, std::string> spam_status_();

  std::string added_headers_(MessageStore const& msg);

  std::ostream& out_() { return sock_.out(); }
  void          lo_(char const* verb, std::string_view client_identity);

  void bad_host_(char const* msg) const __attribute__((noreturn));

  std::string const& server_id_() const { return server_identity_.ascii(); }

  bool forward_to_(std::string const& forward, Mailbox const& rcpt_to);
  bool reply_to_(SRS0::from_to const& reply_info, Mailbox const& rcpt_to);
  bool do_forward_(message::parsed& msg);
  bool do_reply_(message::parsed& msg);
  bool do_deliver_();

  // clear per transaction data, preserve per connection data
  void reset_();

  bool verify_ip_address_(std::string& error_msg);
  bool verify_ip_address_dnsbl_(std::string& error_msg);
  bool verify_client_(Domain const& client_identity, std::string& error_msg);
  bool verify_recipient_(Mailbox const& recipient);
  bool verify_sender_(Mailbox const& sender, std::string& error_msg);
  bool verify_sender_domain_(Domain const& sender, std::string& error_msg);
  bool verify_sender_domain_uribl_(std::string_view sender,
                                   std::string&     error_msg);
  bool verify_sender_spf_(Mailbox const& sender);
  bool verify_from_params_(parameters_t const& parameters);
  bool verify_rcpt_params_(parameters_t const& parameters);

  bool is_forwarding_() const
  {
    return forward_path_.empty() && !fwd_path_.empty();
  }

  void exit_() __attribute__((noreturn));

private:
  fs::path      config_path_;
  DNS::Resolver res_;
  Sock          sock_;

  // forwarding and replies
  Send          send_;
  SRS0          srs_;
  Mailbox       fwd_path_;
  SRS0::from_to rep_info_;

  // per connection/session
  Domain              server_identity_; // who we identify as
  std::vector<Domain> client_fcrdns_;   // who they look-up as
  std::vector<Domain> server_fcrdns_;   // who we look-up as
  std::string         client_;          // (fcrdns_ [sock_.them_c_str()])

  // per transaction
  Domain                        client_identity_; // from ehlo/helo
  Mailbox                       reverse_path_;    // "mail from"
  std::vector<Mailbox>          forward_path_;    // for each "rcpt to"
  std::string                   spf_received_;
  std::unique_ptr<MessageStore> msg_;

  TLD tld_db_;

  std::random_device random_device_;

  // White and black lists for domains.
  CDB white_;
  CDB black_;
  CDB forward_;

  // Domains we receive mail for.
  CDB accept_domains_;

  size_t max_msg_size_;

  int n_unrecognized_cmds_{0};

  SPF::Result spf_result_;
  Domain      spf_sender_domain_;

  // RFC 5321 section 3.3. Mail Transactions
  enum class xact_step : int8_t {
    helo,
    mail,
    rcpt,
    data,
    bdat, // RFC 3030
    rset, // must now send RSET
  };

  // per transaction
  xact_step state_ = xact_step::helo;

  bool binarymime_{false};
  bool extensions_{false};
  bool smtputf8_{false};
  // bool prdr_{false};

  // per connection
  bool fcrdns_whitelisted_{false};
  bool ip_whitelisted_{false};
};

#endif // SESSION_DOT_HPP

#ifndef SESSION_DOT_HPP
#define SESSION_DOT_HPP

#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "Domain.hpp"
#include "Mailbox.hpp"
#include "Message.hpp"
#include "Sock.hpp"
#include "TLD.hpp"

namespace Config {
constexpr size_t kibibyte = 1024;
constexpr size_t mebibyte = kibibyte * kibibyte;
constexpr size_t max_msg_size_initial = 15 * mebibyte;
constexpr size_t max_msg_size_bro = 150 * mebibyte;
} // namespace Config

class Session {
public:
  using parameters_t = std::unordered_map<std::string, std::string>;

  Session(Session const&) = delete;
  Session& operator=(Session const&) = delete;

  explicit Session(std::function<void(void)> read_hook = []() {},
                   int fd_in = STDIN_FILENO,
                   int fd_out = STDOUT_FILENO);

  void greeting();
  void ehlo(std::string_view client_identity);
  void helo(std::string_view client_identity);
  void mail_from(Mailbox&& reverse_path, parameters_t const& parameters);
  void rcpt_to(Mailbox&& forward_path, parameters_t const& parameters);

  bool data_start();
  void data_msg(Message& msg);
  void data_msg_done(Message& msg);
  void data_size_error(Message& msg);

  bool bdat_start();
  void bdat_msg(Message& msg, size_t n);
  void bdat_msg_last(Message& msg, size_t n);
  void bdat_error(Message& msg);

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

  bool maxed_out() { return sock_.maxed_out(); }
  bool timed_out() { return sock_.timed_out(); }
  std::istream& in() { return sock_.in(); }

  void flush();
  void last_in_group_(std::string_view verb);

  size_t max_msg_size() const { return max_msg_size_; }
  void max_msg_size(size_t max)
  {
    max_msg_size_ = max;
    auto const overhead = max / 10;
    sock_.set_max_read(max_msg_size() + overhead);
  }

  void log_stats() { sock_.log_stats(); }

private:
  friend struct Session_test;

  std::string added_headers_(Message const& msg);

  std::ostream& out_() { return sock_.out(); }
  void log_lo_(char const* verb, std::string_view client_identity) const;

  std::string_view server_id_() const { return server_identity_.ascii(); }

  void reset_()
  {
    reverse_path_.clear();
    forward_path_.clear();
    binarymime_ = false;
    extensions_ = false;
    reverse_path_verified_ = false;
  }

  bool verify_ip_address_(std::string& error_msg);
  bool verify_client_(Domain const& client_identity, std::string& error_msg);
  bool verify_recipient_(Mailbox const& recipient);
  bool verify_sender_(Mailbox const& sender);
  bool verify_sender_domain_(Domain const& sender);
  bool verify_sender_domain_uribl_(std::string const& sender);
  bool verify_sender_spf_(Mailbox const& sender);
  bool verify_from_params_(parameters_t const& parameters);

  char const* protocol_();

  void exit_() __attribute__((noreturn));

private:
  Sock sock_;

  size_t max_msg_size_;

  Domain server_identity_;            // who we identify as
  Domain client_fcrdns_;              // who they look-up as
  Domain client_identity_;            // from ehlo/helo
  std::string client_;                // (fcrdns_ [sock_.them_c_str()])
  Mailbox reverse_path_;              // "mail from"
  std::vector<Mailbox> forward_path_; // for each "rcpt to"

  std::string received_spf_; // from libspf2

  std::random_device rd_;

  TLD tld_db_;

  int n_unrecognized_cmds_{0};

  bool binarymime_{false};
  bool extensions_{false};
  bool smtputf8_{false};
  bool fcrdns_whitelisted_{false};
  bool ip_whitelisted_{false};
  bool reverse_path_verified_{false};
};

#endif // SESSION_DOT_HPP

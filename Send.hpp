#ifndef SEND_DOT_HPP
#define SEND_DOT_HPP

#include "DNS.hpp"
#include "Mailbox.hpp"
#include "Sock.hpp"
#include "fs.hpp"

namespace Config {
constexpr auto read_timeout = std::chrono::seconds(30);
constexpr auto write_timeout = std::chrono::minutes(3);
} // namespace Config

namespace RFC5321 {
struct Connection {
  Sock sock;

  std::string server_id;

  std::string                                               ehlo_keyword;
  std::vector<std::string>                                  ehlo_param;
  std::unordered_map<std::string, std::vector<std::string>> ehlo_params;

  std::string reply_code;

  bool greeting_ok{false};
  bool ehlo_ok{false};

  bool has_extension(std::string_view name) const
  {
    return ehlo_params.find("STARTTLS") != end(ehlo_params);
  }

  Connection(int fd_in, int fd_out, std::function<void(void)> read_hook)
    : sock(
        fd_in, fd_out, read_hook, Config::read_timeout, Config::write_timeout)
  {
  }
};
} // namespace RFC5321

class Exchangers {
public:
  RFC5321::Connection& conn(Domain address) { return *exchangers_[address]; }

  bool contains(Domain address) const { return exchangers_.contains(address); }

  void add(Domain dom, std::unique_ptr<RFC5321::Connection> conn)
  {
    exchangers_.insert({dom, std::move(conn)});
  }

private:
  std::unordered_map<Domain, std::unique_ptr<RFC5321::Connection>> exchangers_;
};

class Send {
public:
  Send(fs::path config_path, Domain sender, Domain receiver);

  bool connect(DNS::Resolver& res, Exchangers& exchangers);

  bool mail_from(Exchangers& exchangers, Mailbox from);
  bool rcpt_to(Exchangers& exchangers, Mailbox to);
  bool data(Exchangers& exchangers, char const* data, size_t length);

  void quit(Exchangers& exchangers);

private:
  fs::path config_path_;
  Domain   sender_;
  Domain   receiver_;

  Mailbox              from_;
  std::vector<Mailbox> to_;

  std::vector<Domain> mxs_; // ordered MX list for this receiver_
  Domain              mx_active_;
};

#endif // SEND_DOT_HPP

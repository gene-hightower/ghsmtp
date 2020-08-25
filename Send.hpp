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

  Connection(int fd_in, int fd_out, std::function<void(void)> read_hook)
    : sock(
        fd_in, fd_out, read_hook, Config::read_timeout, Config::write_timeout)
  {
  }
};
} // namespace RFC5321

class Send {
public:
  Send(fs::path config_path, DNS::Resolver& res, Domain sender, Domain domain);

  bool mail_from(Mailbox sender);
  bool rcpt_to(Mailbox recipient);

  bool data(char const* data, size_t length);

  void quit();

private:
  Domain              domain_;
  std::vector<Domain> exchangers_;

  Mailbox              from_;
  std::vector<Mailbox> to_;

  std::unique_ptr<RFC5321::Connection> conn_;
  bool open_session_(DNS::Resolver& res, Domain const& sender);
};

#endif // SEND_DOT_HPP

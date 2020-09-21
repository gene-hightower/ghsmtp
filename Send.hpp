#ifndef SEND_DOT_HPP
#define SEND_DOT_HPP

#include "DNS.hpp"
#include "Mailbox.hpp"
#include "Sock.hpp"
#include "fs.hpp"

namespace SMTP {
struct Connection {
  Connection(int fd_in, int fd_out, std::function<void(void)> read_hook)
    : sock(fd_in,
           fd_out,
           read_hook,
           std::chrono::minutes(2),
           std::chrono::minutes(2))
  {
  }

  Sock sock;

  std::string server_id;

  std::string                                               ehlo_keyword;
  std::vector<std::string>                                  ehlo_param;
  std::unordered_map<std::string, std::vector<std::string>> ehlo_params;

  std::string reply_code;

  bool greeting_ok{false};
  bool ehlo_ok{false};
  bool active{false}; // At least one rcp_to for this MX

  bool has_extension(char const* name) const
  {
    return ehlo_params.find(name) != ehlo_params.end();
  }
};
} // namespace SMTP

class Send {
public:
  Send(fs::path config_path, char const* service);

  void set_sender(Domain sender) { sender_ = sender; }

  bool mail_from_rcpt_to(DNS::Resolver& res,
                         Mailbox const& from,
                         Mailbox const& to,
                         std::string&   error_msg);

  bool send(std::string_view msg);

  void rset();
  void quit();

private:
  fs::path config_path_;
  std::string service_;

  Domain sender_;

  std::unique_ptr<SMTP::Connection> conn_;
};

#endif // SEND_DOT_HPP

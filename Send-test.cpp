#include "Send.hpp"

#include "Now.hpp"
#include "Pill.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);
  google::ParseCommandLineFlags(&argc, &argv, true);

  auto server_identity = [] {
    auto const id_from_env{getenv("GHSMTP_SERVER_ID")};
    if (id_from_env)
      return std::string{id_from_env};

    auto const hostname{osutil::get_hostname()};
    if (hostname.find('.') != std::string::npos)
      return hostname;

    LOG(FATAL) << "can't determine my server ID, set GHSMTP_SERVER_ID maybe";
    return "(none)"s;
  }();

  auto const dom_from{Domain(server_identity)};
  auto const dom_to{Domain(server_identity)};

  auto const config_path = osutil::get_config_dir();

  auto snd{Send(config_path)};
  snd.set_sender(Domain(server_identity));

  Mailbox from("gene", dom_from);
  Mailbox to("forward", dom_to);
  // Mailbox to("anything", dom_to);

  auto const date{Now{}};
  auto const pill{Pill{}};
  auto const mid_str
      = fmt::format("<{}.{}@{}>", date.sec(), pill, server_identity);

  fmt::memory_buffer bfr;
  fmt::format_to(bfr, "Message-ID: {}\r\n", mid_str.c_str());
  fmt::format_to(bfr, "From: \"Gene Hightower\" <{}>\r\n", from.as_string());
  fmt::format_to(bfr, "To: \"Gene Hightower\" <{}>\r\n", to.as_string());
  fmt::format_to(bfr, "Subject: Testing, one, two, three.\r\n");
  fmt::format_to(bfr, "Date: {}\r\n", date.c_str());
  fmt::format_to(bfr, "Authentication-Results: {}; none\r\n", server_identity);

  fmt::format_to(bfr, "\r\n");

  fmt::format_to(bfr, "This is the body of the email.\r\n");
  auto const msg_str = fmt::to_string(bfr);

  auto res{DNS::Resolver{config_path}};

  CHECK(snd.mail_from(from));
  std::string err;
  CHECK(snd.rcpt_to(res, to, err));
  CHECK(snd.send(msg_str));
  snd.quit();
}

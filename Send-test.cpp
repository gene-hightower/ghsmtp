#include "Send.hpp"

#include "Now.hpp"
#include "Pill.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);
  google::ParseCommandLineFlags(&argc, &argv, true);

  auto const dom_from{Domain("digilicious.com")};
  auto const dom_to{Domain("digilicious.com")};

  auto const config_path = osutil::get_config_dir();

  auto snd{Send(config_path)};
  snd.set_sender(Domain("digilicious.com"));

  Mailbox from("gene", dom_from);
  Mailbox to("forward", dom_to);
  // Mailbox to("anything", dom_to);

  auto const date{Now{}};
  auto const pill{Pill{}};
  auto const mid_str
      = fmt::format("<{}.{}@{}>", date.sec(), pill, dom_from.ascii());

  fmt::memory_buffer msg;

  fmt::format_to(msg, "Message-ID: {}\r\n", mid_str.c_str());
  fmt::format_to(msg, "From: \"Gene Hightower\" <{}>\r\n", from.as_string());
  fmt::format_to(msg, "To: \"Gene Hightower\" <{}>\r\n", to.as_string());
  fmt::format_to(msg, "Subject: Testing, one, two, three.\r\n");
  fmt::format_to(msg, "Date: {}\r\n", date.c_str());

  fmt::format_to(msg, "\r\n");

  fmt::format_to(msg, "This is the body of the email.\r\n");
  auto const msg_str = fmt::to_string(msg);

  auto res{DNS::Resolver{config_path}};

  CHECK(snd.mail_from(from));
  std::string err;
  CHECK(snd.rcpt_to(res, to, err));
  CHECK(snd.send(msg_str.data(), msg_str.length()));
  snd.quit();
}

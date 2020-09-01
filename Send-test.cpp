#include "Send.hpp"

#include "ARC.hpp"
#include "Now.hpp"
#include "Pill.hpp"
#include "imemstream.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/iostreams/device/mapped_file.hpp>

using namespace std::string_literals;

void do_arc(char const* dom, char const* msg, size_t len)
{
  ARC::lib arc;

  char const* error = nullptr;

  auto arc_msg = arc.message(ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
                             ARC_SIGN_RSASHA256, ARC_MODE_SIGN, &error);

  imemstream  stream{msg, len};
  std::string line;
  while (std::getline(stream, line)) {
    if(!stream.eof() && !stream.fail()) {
      line.push_back('\n');
    }
    if (line == "\r\n") {
      CHECK_EQ(arc_msg.eoh(), ARC_STAT_OK) << arc_msg.geterror();
      break;
    }
    // LOG(INFO) << "line «" << line << "»";
    CHECK_EQ(arc_msg.header_field(line.data(), line.length()), ARC_STAT_OK)
        << arc_msg.geterror();
  }
  // body
  while (std::getline(stream, line)) {
    if(!stream.eof() && !stream.fail()) {
      line.push_back('\n');
    }
    CHECK_EQ(arc_msg.body(line.data(), line.length()), ARC_STAT_OK)
        << arc_msg.geterror();
  }
  CHECK_EQ(arc_msg.eom(), ARC_STAT_OK) << arc_msg.geterror();

  boost::iostreams::mapped_file_source priv;
  priv.open("ghsmtp.private");

  ARC_HDRFIELD* seal = nullptr;

  CHECK_EQ(arc_msg.seal(&seal, dom, "arc", dom, priv.data(), priv.size(), ""),
           ARC_STAT_OK)
      << arc_msg.geterror();

  if (seal) {
    auto const nam = ARC::hdr::name(seal);
    auto const val = ARC::hdr::value(seal);
    LOG(INFO) << nam << ": " << val;
  }
  else {
    LOG(INFO) << "no seal";
  }
}

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

  do_arc(server_identity.c_str(), msg_str.data(), msg_str.length());

  auto res{DNS::Resolver{config_path}};

  CHECK(snd.mail_from(from));
  std::string err;
  CHECK(snd.rcpt_to(res, to, err));
  CHECK(snd.send(msg_str.data(), msg_str.length()));
  snd.quit();
}

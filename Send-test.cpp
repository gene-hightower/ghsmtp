#include "Send.hpp"

#include "ARC.hpp"
#include "Now.hpp"
#include "Pill.hpp"
#include "imemstream.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/iostreams/device/mapped_file.hpp>

void do_arc(char const* msg, size_t len)
{
  ARC::lib arc;

  char const* error = nullptr;

  auto arc_msg = arc.message(ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
                             ARC_SIGN_RSASHA256, ARC_MODE_SIGN, &error);

  imemstream  stream{msg, len};
  std::string line;
  while (std::getline(stream, line)) {
    if (line == "\r") {
      CHECK_EQ(arc_msg.eoh(), ARC_STAT_OK);
      break;
    }
    LOG(INFO) << "line «" << line << "»";
    CHECK_EQ(arc_msg.header_field(line.data(), line.length()), ARC_STAT_OK);
  }
  // body
  while (std::getline(stream, line)) {
    CHECK_EQ(arc_msg.body(line.data(), line.length()), ARC_STAT_OK);
  }
  CHECK_EQ(arc_msg.eom(), ARC_STAT_OK);

  boost::iostreams::mapped_file_source priv;
  priv.open("private.key");

  auto const dom = "xn--g6h.digilicious.com";
  ARC_HDRFIELD* seal = nullptr;
  auto const ar = "";
  arc_msg.seal(&seal, dom, "arc", dom, priv.data(), priv.size(), ar);
}

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

  fmt::memory_buffer bfr;
  fmt::format_to(bfr, "Message-ID: {}\r\n", mid_str.c_str());
  fmt::format_to(bfr, "From: \"Gene Hightower\" <{}>\r\n", from.as_string());
  fmt::format_to(bfr, "To: \"Gene Hightower\" <{}>\r\n", to.as_string());
  fmt::format_to(bfr, "Subject: Testing, one, two, three.\r\n");
  fmt::format_to(bfr, "Date: {}\r\n", date.c_str());

  fmt::format_to(bfr, "\r\n");

  fmt::format_to(bfr, "This is the body of the email.\r\n");
  auto const msg_str = fmt::to_string(bfr);

  do_arc(msg_str.data(), msg_str.length());

  auto res{DNS::Resolver{config_path}};

  CHECK(snd.mail_from(from));
  std::string err;
  CHECK(snd.rcpt_to(res, to, err));
  CHECK(snd.send(msg_str.data(), msg_str.length()));
  snd.quit();
}

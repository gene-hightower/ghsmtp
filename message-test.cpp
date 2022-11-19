#include "message.hpp"

#include "Now.hpp"
#include "Pill.hpp"
#include "Reply.hpp"
#include "esc.hpp"
#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

#include <boost/iostreams/device/mapped_file.hpp>

#include <iostream>

constexpr char srs_secret[] = "Not a real secret, of course.";

DEFINE_bool(arc, false, "check ARC set");
DEFINE_bool(dkim, false, "check DKIM sigs");
DEFINE_bool(print_from, false, "print envelope froms");

DEFINE_string(selector, "ghsmtp", "DKIM selector");

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  auto server_identity = [] {
    auto const id_from_env{getenv("GHSMTP_SERVER_ID")};
    if (id_from_env)
      return std::string{id_from_env};

    auto const hostname{osutil::get_hostname()};
    if (hostname.find('.') != std::string::npos)
      return hostname;

    LOG(FATAL) << "can't determine my server ID, set GHSMTP_SERVER_ID maybe";
    return std::string("(none)");
  }();

  auto constexpr authentication_results_str =
      "Authentication-Results: digilicious.com;\r\n"
      "       spf=pass smtp.helo=mta122b.pmx1.epsl1.com;\r\n"
      "       dkim=pass header.i=@mail.paypal.com header.s=pp-epsilon1 "
      "header.b=\"A4JA0zWd\";\r\n"
      "       dmarc=fail header.from=mail.paypal.com;\r\n"
      "       arc=none";

  std::string authservid;
  std::string ar_result;
  CHECK(message::authentication_results_parse(authentication_results_str,
                                              authservid, ar_result));
  CHECK_EQ(authservid, "digilicious.com");

  auto const dom_from{Domain(server_identity)};
  auto const dom_to{Domain(server_identity)};

  auto const config_path = osutil::get_config_dir();

  auto const selector = FLAGS_selector.c_str();

  auto const key_file = (config_path / selector).replace_extension("private");
  CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

  Mailbox from("gene", dom_from);
  Mailbox to("anything", dom_to);

  auto const date{Now{}};
  auto const pill{Pill{}};
  auto const mid_str = fmt::format("<{}.{}@{}>", date.sec(),
                                   pill.as_string_view(), server_identity);

  fmt::memory_buffer bfr;
  fmt::format_to(std::back_inserter(bfr), "Message-ID: {}\r\n",
                 mid_str.c_str());
  fmt::format_to(std::back_inserter(bfr), "From: \"Gene Hightower\" <{}>\r\n",
                 from.as_string(Mailbox::domain_encoding::utf8));
  fmt::format_to(std::back_inserter(bfr), "To: \"Gene Hightower\" <{}>\r\n",
                 to.as_string(Mailbox::domain_encoding::utf8));
  fmt::format_to(std::back_inserter(bfr),
                 "Subject: Testing, one, two, three.\r\n");
  fmt::format_to(std::back_inserter(bfr), "Date: {}\r\n", date.c_str());
  fmt::format_to(std::back_inserter(bfr),
                 "Authentication-Results: {}; none\r\n", server_identity);
  fmt::format_to(std::back_inserter(bfr), "MIME-Version: 1.0\r\n");
  fmt::format_to(std::back_inserter(bfr),
                 "Content-Type: text/plain; charset=utf-8\r\n");

  fmt::format_to(std::back_inserter(bfr), "\r\n");

  fmt::format_to(std::back_inserter(bfr), "This is the body of the email.\r\n");
  auto const msg_str = fmt::to_string(bfr);

  message::parsed msg;
  bool const      message_parsed = msg.parse(msg_str);

  if (message_parsed) {
    LOG(INFO) << "message parsed";

    auto const authentic =
        authentication(msg, server_identity.c_str(), selector, key_file);

    if (authentic)
      LOG(INFO) << "authentic";

    Reply::from_to reply;

    reply.mail_from          = msg.dmarc_from;
    reply.rcpt_to_local_part = "local-alias";

    auto const rfc22_from = fmt::format(
        "From: {}@{}", Reply::enc_reply(reply, srs_secret), server_identity);

    auto const reply_to =
        fmt::format("Reply-To: {}@{}", Reply::enc_reply(reply, srs_secret),
                    server_identity);

    message::rewrite_from_to(msg, "", reply_to, server_identity.c_str(),
                             selector, key_file);

    std::cout << msg.as_string();

    // auth again
    // authentication(msg, server_identity.c_str(), selector, key_file);

    auto const count = std::count_if(
        begin(msg.headers), end(msg.headers),
        [](auto const& hdr) { return hdr == message::Authentication_Results; });
    // should have only one header, no matter what
    CHECK_EQ(count, 1);
  }
  else {
    LOG(INFO) << "message failed to parse";
  }

  if (FLAGS_arc) {
    for (int a = 1; a < argc; ++a) {
      if (!fs::exists(argv[a]))
        LOG(FATAL) << "can't find mail file " << argv[a];
      boost::iostreams::mapped_file_source file;
      file.open(argv[a]);
      message::parsed msg;
      CHECK(msg.parse(std::string_view(file.data(), file.size())));
      message::authentication(msg, server_identity.c_str(), selector, key_file);
      std::cout << msg.as_string();
    }
    return 0;
  }

  if (FLAGS_dkim) {
    for (int a = 1; a < argc; ++a) {
      if (!fs::exists(argv[a]))
        LOG(FATAL) << "can't find mail file " << argv[a];
      boost::iostreams::mapped_file_source file;
      file.open(argv[a]);
      message::parsed msg;
      CHECK(msg.parse(std::string_view(file.data(), file.size())));
      message::dkim_check(msg, server_identity.c_str());
    }
    return 0;
  }

  if (FLAGS_print_from) {
    for (int a = 1; a < argc; ++a) {
      if (!fs::exists(argv[a]))
        LOG(FATAL) << "can't find mail file " << argv[a];
      boost::iostreams::mapped_file_source file;
      file.open(argv[a]);
      message::parsed msg;
      CHECK(msg.parse(std::string_view(file.data(), file.size())));
      message::print_spf_envelope_froms(argv[a], msg);
    }
    return 0;
  }

  for (int a = 1; a < argc; ++a) {
    if (!fs::exists(argv[a]))
      LOG(FATAL) << "can't find mail file " << argv[a];
    boost::iostreams::mapped_file_source file;
    file.open(argv[a]);
    message::parsed msg;
    CHECK(msg.parse(std::string_view(file.data(), file.size())));
    rewrite_from_to(msg, "bounce@digilicious.com", "noreply@digilicious.com",
                    server_identity.c_str(), selector, key_file);
    std::cout << msg.as_string();
  }
}

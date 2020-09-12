#include "message.hpp"

#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

#include <boost/iostreams/device/mapped_file.hpp>

#include <iostream>

using namespace std::string_literals;

DEFINE_bool(arc, false, "check ARC set");
DEFINE_bool(dkim, false, "check DKIM sigs");
DEFINE_bool(print_from, false, "print envelope froms");

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  auto const sender = [] {
    auto const id_from_env{getenv("GHSMTP_SERVER_ID")};
    if (id_from_env)
      return std::string{id_from_env};

    auto const hostname{osutil::get_hostname()};
    if (hostname.find('.') != std::string::npos)
      return hostname;

    LOG(FATAL) << "can't determine my server ID, set GHSMTP_SERVER_ID maybe";
    return "(none)"s;
  }();

  auto const config_path = osutil::get_config_dir();

  if (FLAGS_arc) {
    for (int a = 1; a < argc; ++a) {
      if (!fs::exists(argv[a]))
        LOG(FATAL) << "can't find mail file " << argv[a];
      boost::iostreams::mapped_file_source file;
      file.open(argv[a]);
      message::parsed msg;
      CHECK(msg.parse(std::string_view(file.data(), file.size())));
      message::authentication(config_path, sender.c_str(), msg);
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
      message::dkim_check(config_path, sender.c_str(), msg);
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
    message::rewrite(config_path, Mailbox("local-part", sender), Domain(sender),
                     msg);
    std::cout << msg.as_string();
  }
}

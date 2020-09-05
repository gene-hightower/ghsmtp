#include "rewrite.hpp"

#include "osutil.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

#include <boost/iostreams/device/mapped_file.hpp>

#include <iostream>

using namespace std::string_literals;

DEFINE_bool(print_from, false, "print envelope froms");

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);
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

  if (FLAGS_print_from) {
    for (int a = 1; a < argc; ++a) {
      if (!fs::exists(argv[a]))
        LOG(FATAL) << "can't find mail file " << argv[a];

      boost::iostreams::mapped_file_source file;
      file.open(argv[a]);
      print_spf_envelope_froms(argv[a],
                               std::string_view(file.data(), file.size()));
    }
    return 0;
  }

  for (int a = 1; a < argc; ++a) {
    if (!fs::exists(argv[a]))
      LOG(FATAL) << "can't find mail file " << argv[a];

    boost::iostreams::mapped_file_source file;
    file.open(argv[a]);

    auto const rewritten =
        rewrite(sender.c_str(), std::string_view(file.data(), file.size()));

    if (rewritten)
      std::cout << *rewritten;
  }
}

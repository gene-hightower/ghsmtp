#include "Mailbox.hpp"
#include "OpenARC.hpp"
#include "OpenDKIM.hpp"
#include "OpenDMARC.hpp"
#include "esc.hpp"
#include "fs.hpp"
#include "iequal.hpp"
#include "imemstream.hpp"
#include "message.hpp"
#include "osutil.hpp"

#include <cstring>
#include <map>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

using namespace std::string_literals;

bool arc_verify(message::parsed& msg)
{
  CHECK(!msg.headers.empty());

  // ARC

  OpenARC::verify arv;
  for (auto const& header : msg.headers) {
    arv.header(header.as_view());
  }
  arv.eoh();
  arv.body(msg.body);
  arv.eom();

  LOG(INFO) << "ARC status  == " << arv.chain_status_str();
  LOG(INFO) << "ARC custody == " << arv.chain_custody_str();

  return "fail"s != arv.chain_status_str();
}

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  auto const server_identity = [] {
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

  for (int a = 1; a < argc; ++a) {
    if (!fs::exists(argv[a]))
      LOG(FATAL) << "can't find mail file " << argv[a];
    boost::iostreams::mapped_file_source file;
    file.open(argv[a]);
    message::parsed msg;
    CHECK(msg.parse(std::string_view(file.data(), file.size())));
    arc_verify(msg);
    // std::cout << msg.as_string();
  }
}

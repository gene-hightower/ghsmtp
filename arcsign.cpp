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

DEFINE_string(signer, "digilicious.com", "signing domain");
DEFINE_string(selector, "ghsmtp", "DKIM selector");

bool arc_sign(message::parsed& msg,
              char const*      sender,
              char const*      selector,
              fs::path         key_file,
              char const*      server_id)
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

  auto const arc_status = arv.chain_status_str();

  // Run our message through ARC::sign

  OpenARC::sign ars;

  if (iequal(arc_status, "none")) {
    ars.set_cv_none();
  }
  else if (iequal(arc_status, "fail")) {
    ars.set_cv_fail();
  }
  else if (iequal(arc_status, "pass")) {
    ars.set_cv_pass();
  }
  else {
    ars.set_cv_unkn();
  }

  for (auto const& header : msg.headers) {
    ars.header(header.as_view());
  }
  ars.eoh();
  ars.body(msg.body);
  ars.eom();

  boost::iostreams::mapped_file_source priv;
  priv.open(key_file);

  std::string ar_results = "None";
  for (auto hdr : msg.headers) {
    if (hdr == message::Authentication_Results) {
      std::string authservid;
      if (message::authentication_results_parse(hdr.as_view(), authservid,
                                                ar_results)) {
        if (Domain::match(authservid, sender))
          break;
        LOG(INFO) << "ignoring AR: " << hdr.as_string();
      }
      LOG(WARNING) << "failed to parse «"
                   << esc(hdr.as_string(), esc_line_option::multi) << "»";
      ar_results = "None";
    }
  }

  if (ars.seal(sender, selector, sender, priv.data(), priv.size(),
               ar_results.c_str())) {
    msg.arc_hdrs = ars.whole_seal();
    for (auto const& hdr : msg.arc_hdrs) {
      CHECK(msg.parse_hdr(hdr));
    }
  }
  else {
    LOG(INFO) << "failed to generate seal";
  }

  OpenARC::verify arv2;
  for (auto const& header : msg.headers) {
    arv2.header(header.as_view());
  }
  arv2.eoh();
  arv2.body(msg.body);
  arv2.eom();

  LOG(INFO) << "check ARC status  == " << arv2.chain_status_str();
  LOG(INFO) << "check ARC custody == " << arv2.chain_custody_str();

  return "fail"s != arv2.chain_status_str();
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

  auto const selector = FLAGS_selector.c_str();

  auto const key_file = (config_path / selector).replace_extension("private");
  CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

  auto const dom_signer{Domain(FLAGS_signer)};

  for (int a = 1; a < argc; ++a) {
    if (!fs::exists(argv[a]))
      LOG(FATAL) << "can't find mail file " << argv[a];
    boost::iostreams::mapped_file_source file;
    file.open(argv[a]);
    message::parsed msg;
    CHECK(msg.parse(std::string_view(file.data(), file.size())));
    CHECK(arc_sign(msg, dom_signer.ascii().c_str(), selector, key_file,
                   server_identity.c_str()));
    std::cout << msg.as_string();
  }
}

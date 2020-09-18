#include "SRS0.hpp"

#include "osutil.hpp"

#include <iostream>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  fs::path config_path = osutil::get_config_dir();

  SRS0 srs(config_path);

  SRS0::from_to test_cases[] = {
      {"reply@example.com", "local-address"},
      {"reply=something@example.com", "local"},
      {"one.reply@example.com", "local"},
      {"reply@example.com", "local"},
      {"reply@example.com", "local=address"},
      {"\"quoted string\"@example.com", "local"},
      {"reply@[127.0.0.1]", "local"},
  };

  for (auto const& test_case : test_cases) {
    auto const enc_rep = srs.enc_reply(test_case);
    auto const dec_rep = srs.dec_reply(enc_rep);
    if (!dec_rep || *dec_rep != test_case) {
      LOG(INFO) << "in  mail_from  == " << test_case.mail_from;
      LOG(INFO) << "in  local_part == " << test_case.rcpt_to_local_part;
      LOG(INFO) << "    enc_rep    == " << enc_rep;
      LOG(INFO) << "out mail_from  == " << dec_rep->mail_from;
      LOG(INFO) << "out local_part == " << dec_rep->rcpt_to_local_part;
      CHECK(test_case == *dec_rep);
    }
  }

  for (auto const& test_case : test_cases) {
    auto const enc_bnc = srs.enc_bounce(test_case, "sender.com");
    auto const dec_bnc = srs.dec_bounce(enc_bnc, 3);
    if (!dec_bnc || dec_bnc->mail_from != test_case.mail_from) {
      LOG(INFO) << "in  mail_from  == " << test_case.mail_from;
      LOG(INFO) << "    enc_bnc    == " << enc_bnc;
      LOG(INFO) << "out mail_from  == " << dec_bnc->mail_from;
    }
  }
}

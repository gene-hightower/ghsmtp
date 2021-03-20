#include "SRS0.hpp"

#include "Mailbox.hpp"
#include "osutil.hpp"

#include <iostream>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

#include <cppcodec/base32_crockford.hpp>
#include <openssl/sha.h>

using std::begin;
using std::end;

constexpr char srs_secret[] = "Not a real secret, of course.";

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK_EQ(SRS0::enc_reply({"x@y.z", "a"}, srs_secret), "rep=RHGA7M=a=x=y.z");
  CHECK_EQ(SRS0::enc_reply({"x=x@y.z", "a"}, srs_secret),
           "rep=A0DT6K=a=x=x=y.z");
  CHECK_EQ(SRS0::enc_reply({"x@y.z", "a=a"}, srs_secret),
           "rep=6NBM8PA4AR062FB101W40Y9EF8");
  CHECK_EQ(SRS0::enc_reply({"\"x\"@y.z", "a"}, srs_secret),
           "rep=AWTK8DJQAW062012F0H40Y9EF8");
  CHECK_EQ(SRS0::enc_reply({"x@[IPv6:::1]", "a"}, srs_secret),
           "rep=8GWKGGAD8C06203R81DMJM3P6RX3MEHHBM");

  SRS0::from_to test_cases[] = {
      {"reply@example.com", "local"},
      {"reply@example.com", "local-address"},
      {"one.reply@example.com", "local"},
      {"reply=something@example.com", "local"},

      // Should work with UTF-8 in all the places.
      {"♥@♥.example.com", "♥"},

      // These should force blob mode:
      {"reply@example.com", "separator=in=address"},
      {"\"quoted string\"@example.com", "local"},
      {"reply@[127.0.0.1]", "local"},
      {"reply@[IPv6:::1]", "local"},
  };

  for (auto const& test_case : test_cases) {
    auto const enc_rep = SRS0::enc_reply(test_case, srs_secret);
    // std::cout << enc_rep << '\n';
    CHECK(Mailbox::validate(fmt::format("{}@x.y", enc_rep))) << enc_rep;
    auto const dec_rep = SRS0::dec_reply(enc_rep, srs_secret);
    if (!dec_rep || *dec_rep != test_case) {
      LOG(INFO) << "in  mail_from  == " << test_case.mail_from;
      LOG(INFO) << "in  local_part == " << test_case.rcpt_to_local_part;
      LOG(INFO) << "    enc_rep    == " << enc_rep;
      LOG(INFO) << "out mail_from  == " << dec_rep->mail_from;
      LOG(INFO) << "out local_part == " << dec_rep->rcpt_to_local_part;
      CHECK(test_case == *dec_rep);
    }
  }
}

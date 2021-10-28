#include "Reply.hpp"

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

constexpr char secret[] = "Not a real secret, of course.";

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  // const Reply::from_to y0{"x@y.z", "a"};
  // auto const           x0 = Reply::dec_reply("rep=RHGA7M=a=x=y.z", secret);
  // if (*x0 != y0) {
  //   CHECK(y0 == *x0);
  // }
  // const Reply::from_to y1{"x@y.z", "a=a"};
  // auto const x1 = Reply::dec_reply("rep=6NBM8PA4AR062FB101W40Y9EF8", secret);
  // if (*x1 != y1) {
  //   CHECK(y1 == *x1);
  // }
  // auto const z1 = Reply::dec_reply("rep=6nbm8pa4ar062fb101w40y9ef8", secret);
  // if (*x1 != z1) {
  //   CHECK(z1 == *x1);
  // }

  // LOG(INFO) << Reply::enc_reply({"someone@example.com", "dab-dab"}, secret);

  // LOG(INFO) << Reply::enc_reply({"anybody@mailhog.duck", "mydisabledalias"},
  //                               secret);
  // LOG(INFO) << Reply::enc_reply({"x@y.z", "a"}, secret);

  CHECK_EQ(Reply::enc_reply({"x@y.z", "a"}, secret), "x_at_y.z_rhga7m_a");
  CHECK_EQ(Reply::enc_reply({"x_x@y.z", "a"}, secret), "x_x_at_y.z_4797dj_a");
  CHECK_EQ(Reply::enc_reply({"x=x@y.z", "a"}, secret), "x=x_at_y.z_a0dt6k_a");
  CHECK_EQ(Reply::enc_reply({"x=x@y.z", "a_a"}, secret),
           "x=x=at=y.z=2a2qpd=a_a");
  CHECK_EQ(Reply::enc_reply({"x.x@y.z", "a"}, secret), "x.x_at_y.z_9avgdj_a");
  CHECK_EQ(Reply::enc_reply({"x@y.z", "a=a"}, secret), "x_at_y.z_5wdydv_a=a");
  CHECK_EQ(Reply::enc_reply({"x@y.z", "a_a"}, secret), "x=at=y.z=3d8qs3=a_a");
  CHECK_EQ(Reply::enc_reply({"\"x\"@y.z", "a"}, secret),
           "ewtk8dkqew062012f0h40y9ef8");
  CHECK_EQ(Reply::enc_reply({"x@[IPv6:::1]", "a"}, secret),
           "cgwkgrbdcc06203r81dmjm3p6rx3mehhbm");

  Reply::from_to test_cases[] = {
      {"reply@example.com", "local"},
      {"reply@example.com", "local_address"},
      {"reply@example.com", "local-address"},
      {"reply@example.com", "local=address"},
      {"one.reply@example.com", "local"},
      {"one-reply@example.com", "local"},
      {"one=reply@example.com", "local"},
      {"one_reply@example.com", "local"},
      {"reply=something@example.com", "local"},

      // Should work with UTF-8 in all the places.
      {"♥@♥.example.com", "♥"},

      // These should force blob mode:
      {"reply@example.com", "\"local part\""},
      {"reply@example.com", "has=both_separators"},
      {"\"quoted string\"@example.com", "local"},
      {"reply@[127.0.0.1]", "local"},
      {"reply@[IPv6:::1]", "local"},
  };

  for (auto const& test_case : test_cases) {
    auto const enc_rep = Reply::enc_reply(test_case, secret);
    // std::cout << enc_rep << '\n';
    CHECK(Mailbox::validate(fmt::format("{}@x.y", enc_rep))) << enc_rep;
    auto const dec_rep = Reply::dec_reply(enc_rep, secret);
#if 0
    if (!dec_rep || *dec_rep != test_case) {
      LOG(INFO) << "in  mail_from  == " << test_case.mail_from;
      LOG(INFO) << "in  local_part == " << test_case.rcpt_to_local_part;
      LOG(INFO) << "    enc_rep    == " << enc_rep;
      LOG(INFO) << "out mail_from  == " << dec_rep->mail_from;
      LOG(INFO) << "out local_part == " << dec_rep->rcpt_to_local_part;
      CHECK(test_case == *dec_rep);
    }
#endif
  }
}

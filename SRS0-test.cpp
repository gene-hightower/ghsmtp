#include "SRS0.hpp"

#include <iostream>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <gflags/gflags.h>

#include <glog/logging.h>

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  google::ParseCommandLineFlags(&argc, &argv, true);

  SRS0 srs;

  auto const rep_enc =
      srs.enc_reply(SRS0::reply_address{"foo@example.com", "local"});

  std::cout << rep_enc << '\n';

  auto const rep_dec = srs.dec_reply(rep_enc);
  CHECK(rep_dec);

  std::cout << rep_dec->mail_from << '\n';
  std::cout << rep_dec->rcpt_to_local_part << '\n';

  auto const bnc_enc = srs.enc_bounce(SRS0::bounce_address{"foo@example.com"});

  std::cout << bnc_enc << '\n';

  auto const bnc_dec = srs.dec_bounce(bnc_enc, 10);
  CHECK(bnc_dec);

  std::cout << bnc_dec->mail_from << '\n';
}

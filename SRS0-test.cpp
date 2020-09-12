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

  auto const enc =
      srs.enc_reply(SRS0::reply_address{"foo@example.com", "local"});

  std::cout << enc << '\n';

  auto const dec = srs.dec_reply(enc);
  if (dec) {
    std::cout << dec->mail_from << '\n';
    std::cout << dec->rcpt_to_local_part << '\n';
  }
}

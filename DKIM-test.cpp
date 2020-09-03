#include "DKIM.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>

#include <fmt/format.h>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  auto const body_type = DKIM::Sign::body_type::text;

  auto const    key_file = "ghsmtp.private";
  std::ifstream keyfs(key_file);
  CHECK(keyfs.good()) << "can't access " << key_file;

  std::string key(std::istreambuf_iterator<char>{keyfs}, {});

  DKIM::Sign dks(key.c_str(), "ghsmtp", "digilicious.com", body_type);

  dks.header("from: gene@digilicious.com");
  dks.header("to: gene@digilicious.com");
  dks.eoh();

  dks.body("foo\r\nbar\r\nbaz\r\n");
  dks.eom();

  fmt::print("DKIM-Signature: {}\n", dks.getsighdr());
}

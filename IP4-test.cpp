#include "IP4.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK(IP4::is_address_literal("[69.0.0.0]"));
  CHECK(!IP4::is_address_literal("69.0.0.0]"));
  CHECK(!IP4::is_address_literal("[69.0.0.0"));
  CHECK(!IP4::is_address_literal("[]"));
  CHECK(!IP4::is_address_literal("[1234]"));

  CHECK(IP4::is_address("0.0.0.0"));
  CHECK(IP4::is_address("69.0.0.0"));
  CHECK(IP4::is_address("160.0.0.0"));
  CHECK(IP4::is_address("250.0.0.0"));
  CHECK(IP4::is_address("251.0.0.0"));
  CHECK(IP4::is_address("252.0.0.0"));
  CHECK(IP4::is_address("253.0.0.0"));
  CHECK(IP4::is_address("254.0.0.0"));
  CHECK(IP4::is_address("111.0.0.0"));

  CHECK(IP4::is_address("9.9.9.9"));
  CHECK(IP4::is_address("99.99.99.99"));
  CHECK(IP4::is_address("255.0.0.1"));
  CHECK(IP4::is_address("127.0.0.1"));

  CHECK(!IP4::is_address("127.0.0.1."));
  CHECK(!IP4::is_address("foo.bar"));
  CHECK(!IP4::is_address(""));

  // This is acceptable:
  CHECK(IP4::is_address("001.0.0.0"));
  // but not:
  CHECK(!IP4::is_address("0001.0.0.0"));
  // or:
  CHECK(!IP4::is_address("00001.0.0.0"));

  CHECK(!IP4::is_address("256.0.0.0"));
  CHECK(!IP4::is_address("260.0.0.0"));
  CHECK(!IP4::is_address("300.0.0.0"));
  CHECK(!IP4::is_address("1000.0.0.0"));

  CHECK(!IP4::is_address("1.256.0.0"));
  CHECK(!IP4::is_address("1.260.0.0"));
  CHECK(!IP4::is_address("1.300.0.0"));
  CHECK(!IP4::is_address("1.1000.0.0"));

  CHECK(!IP4::is_address("1.1.256.0"));
  CHECK(!IP4::is_address("1.1.260.0"));
  CHECK(!IP4::is_address("1.1.300.0"));
  CHECK(!IP4::is_address("1.1.1000.0"));

  CHECK(!IP4::is_address("1.1.1.256"));
  CHECK(!IP4::is_address("1.1.1.260"));
  CHECK(!IP4::is_address("1.1.1.300"));
  CHECK(!IP4::is_address("1.1.1.1000"));

  std::string reverse{IP4::reverse("1.2.3.4")};
  CHECK_EQ(0, reverse.compare("4.3.2.1."));
}

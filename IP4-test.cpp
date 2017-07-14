#include "IP4.hpp"

#include <glog/logging.h>

using namespace std::string_literals;

using namespace IP4;

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK(is_address_literal("[69.0.0.0]"));
  CHECK(!is_address_literal("69.0.0.0]"));
  CHECK(!is_address_literal("[69.0.0.0"));
  CHECK(!is_address_literal("[]"));
  CHECK(!is_address_literal("[1234]"));

  CHECK(is_address("0.0.0.0"));
  CHECK(is_address("69.0.0.0"));
  CHECK(is_address("160.0.0.0"));
  CHECK(is_address("250.0.0.0"));
  CHECK(is_address("251.0.0.0"));
  CHECK(is_address("252.0.0.0"));
  CHECK(is_address("253.0.0.0"));
  CHECK(is_address("254.0.0.0"));
  CHECK(is_address("111.0.0.0"));

  CHECK(is_address("9.9.9.9"));
  CHECK(is_address("99.99.99.99"));
  CHECK(is_address("255.0.0.1"));
  CHECK(is_address("127.0.0.1"));

  CHECK(!is_address("127.0.0.1."));
  CHECK(!is_address("foo.bar"));
  CHECK(!is_address(""));

  // This is acceptable:
  CHECK(is_address("001.0.0.0"));
  // but not:
  CHECK(!is_address("0001.0.0.0"));
  // or:
  CHECK(!is_address("00001.0.0.0"));

  CHECK(!is_address("256.0.0.0"));
  CHECK(!is_address("260.0.0.0"));
  CHECK(!is_address("300.0.0.0"));
  CHECK(!is_address("1000.0.0.0"));

  CHECK(!is_address("1.256.0.0"));
  CHECK(!is_address("1.260.0.0"));
  CHECK(!is_address("1.300.0.0"));
  CHECK(!is_address("1.1000.0.0"));

  CHECK(!is_address("1.1.256.0"));
  CHECK(!is_address("1.1.260.0"));
  CHECK(!is_address("1.1.300.0"));
  CHECK(!is_address("1.1.1000.0"));

  CHECK(!is_address("1.1.1.256"));
  CHECK(!is_address("1.1.1.260"));
  CHECK(!is_address("1.1.1.300"));
  CHECK(!is_address("1.1.1.1000"));

  std::string rev{reverse("1.2.3.4"s)};
  CHECK_EQ(0, rev.compare("4.3.2.1."s));

  auto addr = "108.83.36.113"s;
  auto addr_lit = "[108.83.36.113]"s;

  CHECK(is_address(addr));
  CHECK(is_address_literal(addr_lit));

  CHECK_EQ(to_address_literal(addr), addr_lit);
  CHECK_EQ(to_address(addr_lit), addr);
}

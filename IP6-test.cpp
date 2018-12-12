#include "IP6.hpp"

#include "Domain.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  using IP6::as_address;
  using IP6::is_address;
  using IP6::is_address_literal;
  using IP6::is_private;
  using IP6::to_address_literal;

  CHECK(is_address("::1"));
  CHECK(is_address_literal("[IPv6:::1]"));

  CHECK(is_address("::ffff:0.0.0.0"));
  CHECK(is_address("::ffff:255.255.255.255"));

  CHECK(is_address("::ffff:0:0.0.0.0"));
  CHECK(is_address("::ffff:0:255.255.255.255"));

  CHECK(is_address("fd12:3456:789a:1::1"));

  auto const addr{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"};
  auto const addr_lit{"[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]"};

  CHECK(is_address(addr));
  CHECK(is_address_literal(addr_lit));

  CHECK(!is_private(addr));
  CHECK(is_private("fd12:3456:789a:1::1"));

  CHECK_EQ(to_address_literal(addr), addr_lit);
  CHECK_EQ(as_address(addr_lit), addr);
}

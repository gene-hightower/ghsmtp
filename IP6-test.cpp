#include "IP6.hpp"

#include <glog/logging.h>

using namespace IP6;

int main(int argc, char const* argv[])
{
  CHECK(is_address("::1"));
  CHECK(is_address_literal("[IPv6:::1]"));

  auto const addr{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"};
  auto const addr_lit{"[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]"};

  CHECK(is_address(addr));
  CHECK(is_address_literal(addr_lit));

  CHECK_EQ(to_address_literal(addr), addr_lit);
  CHECK_EQ(to_address(addr_lit), addr);
}

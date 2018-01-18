#include "IP6.hpp"

#include "Domain.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  using namespace IP6;

  CHECK(is_address("::1"));
  CHECK(is_address_literal("[IPv6:::1]"));

  auto const addr{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"};
  auto const addr_lit{"[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]"};

  CHECK(is_address(addr));
  CHECK(is_address_literal(addr_lit));

  CHECK_EQ(to_address_literal(addr), addr_lit);
  CHECK_EQ(to_address(addr_lit), addr);

  // This is going to break someday.  I added this test Jan 17th 2018.

  auto const gmail_com{"2607:f8b0:4000:815::2005"};
  auto const gmail_com_rev{fcrdns(gmail_com)};
  CHECK(Domain::match(gmail_com_rev, "dfw28s04-in-x05.1e100.net."))
      << gmail_com_rev;
}

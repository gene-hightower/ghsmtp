#include "IP.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <glog/logging.h>

namespace IP {
bool is_address(std::experimental::string_view addr)
{
  return IP4::is_address(addr) || IP6::is_address(addr);
}

bool is_address_literal(std::experimental::string_view addr)
{
  return IP4::is_address_literal(addr) || IP6::is_address_literal(addr);
}

std::string to_address_literal(std::experimental::string_view addr)
{
  if (IP4::is_address(addr))
    return IP4::to_address_literal(addr);
  if (IP6::is_address(addr))
    return IP6::to_address_literal(addr);
  LOG(FATAL) << "not a valid IP address " << addr;
}

std::experimental::string_view to_address(std::experimental::string_view addr)
{
  if (IP4::is_address_literal(addr))
    return IP4::to_address(addr);
  if (IP6::is_address_literal(addr))
    return IP6::to_address(addr);
  LOG(FATAL) << "not a valid IP address literal " << addr;
}

std::string reverse(std::experimental::string_view addr)
{
  if (IP4::is_address(addr))
    return IP4::reverse(addr);
  if (IP6::is_address(addr))
    return IP6::reverse(addr);
  LOG(FATAL) << "not a valid IP address " << addr;
}

std::string fcrdns(DNS::Resolver& res, char const* addr)
{
  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  if (IP4::is_address(addr))
    return IP4::fcrdns(res, addr);
  if (IP6::is_address(addr))
    return IP6::fcrdns(res, addr);
  LOG(FATAL) << "not a valid IP address " << addr;
}
}

#include "DNS-fcrdns.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <glog/logging.h>

// <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

namespace DNS {

std::vector<std::string> fcrdns4(Resolver& res, std::string_view addr)
{
  auto const reversed{IP4::reverse(addr)};

  // The reverse part, check PTR records.
  auto const ptrs = res.get_strings(RR_type::PTR, reversed + "in-addr.arpa");

  std::vector<std::string> fcrdns;

  std::copy_if(ptrs.begin(), ptrs.end(), std::back_inserter(fcrdns),
               [&res, addr](std::string const& s) {
                 // The forward part, check each PTR for matching A record.
                 auto const addrs = res.get_strings(RR_type::A, s);
                 return std::find(addrs.begin(), addrs.end(), addr)
                        != addrs.end();
               });

  // Sort by name length: short to long.
  std::sort(fcrdns.begin(), fcrdns.end(),
            [](std::string const& a, std::string const& b) {
              return a.length() < b.length();
            });

  return fcrdns;
}

std::vector<std::string> fcrdns6(Resolver& res, std::string_view addr)
{
  auto const reversed{IP6::reverse(addr)};

  // The reverse part, check PTR records.
  auto const ptrs = res.get_strings(RR_type::PTR, reversed + "ip6.arpa");

  std::vector<std::string> fcrdns;

  std::copy_if(ptrs.begin(), ptrs.end(), std::back_inserter(fcrdns),
               [&res, addr](std::string const& s) {
                 // The forward part, check each PTR for matching AAAA record.
                 auto addrs = res.get_strings(RR_type::AAAA, s);
                 return std::find(addrs.begin(), addrs.end(), addr)
                        != addrs.end();
               });

  // Sort by name length: short to long.
  std::sort(fcrdns.begin(), fcrdns.end(),
            [](std::string const& a, std::string const& b) {
              return a.length() < b.length();
            });

  return fcrdns;
}

std::vector<std::string> fcrdns(Resolver& res, std::string_view addr)
{
  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  if (IP4::is_address(addr))
    return fcrdns4(res, addr);
  if (IP6::is_address(addr))
    return fcrdns6(res, addr);
  LOG(FATAL) << "not a valid IP address " << addr;
}
} // namespace DNS

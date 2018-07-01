#include "DNS-fcrdns.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

#include <algorithm>

#include <glog/logging.h>

// <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

namespace DNS {

std::vector<std::string> fcrdns4(Resolver& res, std::string_view addr)
{
  auto const reversed{IP4::reverse(addr)};

  // The reverse part, check PTR records.
  auto const ptrs = res.get_records(RR_type::PTR, reversed + "in-addr.arpa");

  std::vector<std::string> fcrdns;

  for (auto const& ptr : ptrs) {
    if (std::holds_alternative<DNS::RR_PTR>(ptr)) {
      // The forward part, check each PTR for matching A record.
      auto const addrs
          = res.get_strings(RR_type::A, std::get<DNS::RR_PTR>(ptr).str());
      if (std::find(begin(addrs), end(addrs), addr) != end(addrs)) {
        fcrdns.push_back(std::get<DNS::RR_PTR>(ptr).str());
      }
    }
  }

  // Sort 1st by name length: short to long.
  std::sort(begin(fcrdns), end(fcrdns),
            [](std::string_view a, std::string_view b) {
              if (a.length() != b.length())
                return a.length() < b.length();
              return a < b;
            });

  std::unique(begin(fcrdns), end(fcrdns));

  return fcrdns;
}

std::vector<std::string> fcrdns6(Resolver& res, std::string_view addr)
{
  auto const reversed{IP6::reverse(addr)};

  // The reverse part, check PTR records.
  auto const ptrs = res.get_records(RR_type::PTR, reversed + "ip6.arpa");

  std::vector<std::string> fcrdns;

  for (auto const& ptr : ptrs) {
    if (std::holds_alternative<DNS::RR_PTR>(ptr)) {
      // The forward part, check each PTR for matching AAAA record.
      auto const addrs
          = res.get_strings(RR_type::AAAA, std::get<DNS::RR_PTR>(ptr).str());
      if (std::find(begin(addrs), end(addrs), addr) != end(addrs)) {
        fcrdns.push_back(std::get<DNS::RR_PTR>(ptr).str());
      }
    }
  }

  // Sort 1st by name length: short to long.
  std::sort(begin(fcrdns), end(fcrdns), [](auto a, auto b) {
    if (size(a) != size(b))
      return size(a) < size(b);
    return a < b;
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

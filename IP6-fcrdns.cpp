#include "IP6.hpp"

#include <glog/logging.h>

#include "DNS.hpp"

namespace IP6 {

std::vector<std::string> fcrdns(std::string_view addr)
{
  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto const reversed{reverse(addr)};

  // The reverse part, check PTR records.
  auto res{DNS::Resolver{}};
  auto const ptrs = res.get_strings(DNS::RR_type::PTR, reversed + "ip6.arpa");

  std::vector<std::string> fcrdns;

  std::copy_if(ptrs.begin(), ptrs.end(), std::back_inserter(fcrdns),
               [&res, addr](std::string const& s) {
                 // The forward part, check each PTR for matching AAAA record.
                 auto addrs = res.get_strings(DNS::RR_type::AAAA, s);
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
} // namespace IP6

#include "IP4.hpp"

#include "DNS.hpp"

#include <boost/xpressive/xpressive.hpp>

#include <glog/logging.h>

using namespace std::string_literals;

namespace IP4 {

inline boost::xpressive::cregex single_octet()
{
  using namespace boost::xpressive;

  // clang-format off
  return (as_xpr('2') >> '5' >> range('0', '5'))  // 250->255
         | ('2' >> range('0', '4') >> _d)         // 200->249
         | (range('0', '1') >> repeat<2>(_d))     // 000->199
         | repeat<1, 2>(_d);                      //   0->99
  // clang-format on
}

bool is_address(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re = octet >> '.' >> octet >> '.' >> octet >> '.' >> octet;
  cmatch matches;
  return regex_match(addr.begin(), addr.end(), matches, re);
}

bool is_address_literal(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re
      = '[' >> octet >> '.' >> octet >> '.' >> octet >> '.' >> octet >> ']';
  cmatch matches;
  return regex_match(addr.begin(), addr.end(), matches, re);
}

std::string to_address_literal(std::experimental::string_view addr)
{
  CHECK(is_address(addr));
  return "["s + std::string(addr.data(), addr.size()) + "]"s;
}

std::string to_address(std::experimental::string_view addr)
{
  CHECK(is_address_literal(addr));
  auto ret = std::string(addr.data(), addr.size());
  ret.erase(ret.begin());
  ret.erase(ret.end() - 1);
  return ret;
}

std::string reverse(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re = (s1 = octet) >> '.' >> (s2 = octet) >> '.' >> (s3 = octet) >> '.'
              >> (s4 = octet);
  cmatch matches;
  CHECK(regex_match(addr.begin(), addr.end(), matches, re))
      << "IP4::reverse called with bad dotted quad: " << addr;

  std::ostringstream reverse;
  for (int n = 4; n > 0; --n) {
    std::experimental::string_view octet(matches[n].first,
                                         matches[n].second - matches[n].first);
    reverse << octet << '.'; // and leave a trailing '.'
  }
  return reverse.str();
}

std::string fcrdns(char const* addr)
{
  using namespace DNS;
  Resolver res;

  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto reversed = reverse(addr);

  // The reverse part, check PTR records.
  auto ptrs = get_records<RR_type::PTR>(res, reversed + "in-addr.arpa");

  auto ptr = std::find_if(
      ptrs.begin(), ptrs.end(), [&res, addr](std::string const& s) {
        // The forward part, check each PTR for matching A record.
        std::vector<std::string> addrs = get_records<RR_type::A>(res, s);
        return std::find(addrs.begin(), addrs.end(), addr) != addrs.end();
      });

  if (ptr != ptrs.end()) {
    return *ptr;
  }
  return "";
}
}

#include "IP6.hpp"

#include "DNS.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

#include <glog/logging.h>

namespace IP6 {

using dot = one<'.'>;
using colon = one<':'>;

// clang-format off
struct dec_octet : sor<one<'0'>,
                       rep_min_max<1, 2, DIGIT>,
                       seq<one<'1'>, DIGIT, DIGIT>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<string<'2','5'>, range<'0','5'>>> {};
// clang-format on

struct ipv4_address
  : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {
};

struct h16 : rep_min_max<1, 4, HEXDIG> {
};

struct ls32 : sor<seq<h16, colon, h16>, ipv4_address> {
};

struct dcolon : two<':'> {
};

// clang-format off
struct ipv6_address : sor<seq<                                          rep<6, h16, colon>, ls32>,
                          seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                          seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>, 
                          seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                          seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                          seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                          seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};
// clang-format on

struct ipv6_address_literal : seq<TAOCPP_PEGTL_ISTRING(lit_pfx),
                                  ipv6_address,
                                  TAOCPP_PEGTL_ISTRING(lit_sfx)> {
};

struct ipv6_address_only : seq<ipv6_address, eof> {
};
struct ipv6_address_literal_only : seq<ipv6_address_literal, eof> {
};

bool is_private(std::string_view addr) { return false; } // Lie!

bool is_address(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "ip6"}};
  return parse<IP6::ipv6_address_only>(in);
}

bool is_address_literal(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "ip6"}};
  return parse<IP6::ipv6_address_literal_only>(in);
}

std::string to_address_literal(std::string_view addr)
{
  CHECK(is_address(addr));
  auto ss{std::stringstream{}};
  ss << lit_pfx << addr << lit_sfx;
  return ss.str();
}

std::string reverse(std::string_view addr_str)
{
  auto addr{in6_addr{}};

  static_assert(sizeof(addr) == 16, "in6_addr is the wrong size");

  auto const addr_void{reinterpret_cast<void*>(&addr)};
  auto const addr_uint{reinterpret_cast<uint8_t const*>(&addr)};

  CHECK_EQ(1, inet_pton(AF_INET6, addr_str.data(), addr_void));

  auto q{std::string{}};
  q.reserve(2 * NS_IN6ADDRSZ);

  for (auto n = NS_IN6ADDRSZ - 1; n >= 0; --n) {
    auto const ch = addr_uint[n];

    auto const lo = ch & 0xF;
    auto const hi = (ch >> 4) & 0xF;

    auto constexpr hex_digits = "0123456789abcdef";

    q += hex_digits[lo];
    q += '.';
    q += hex_digits[hi];
    q += '.';
  }

  return q;
}

std::string fcrdns(std::string_view addr)
{
  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto const reversed{reverse(addr)};

  // The reverse part, check PTR records.
  auto res{DNS::Resolver{}};
  auto const ptrs
      = DNS::get_strings<DNS::RR_type::PTR>(res, reversed + "ip6.arpa");

  auto const ptr = std::find_if(
      ptrs.begin(), ptrs.end(), [&res, addr](std::string const& s) {
        // The forward part, check each PTR for matching AAAA record.
        auto addrs = DNS::get_strings<DNS::RR_type::AAAA>(res, s);
        return std::find(addrs.begin(), addrs.end(), addr) != addrs.end();
      });

  if (ptr != ptrs.end()) {
    return *ptr;
  }
  return "";
}
} // namespace IP6

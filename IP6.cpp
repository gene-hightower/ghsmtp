#include "IP6.hpp"

#include "DNS.hpp"

#include <fmt/format.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using tao::pegtl::eof;
using tao::pegtl::memory_input;
using tao::pegtl::one;
using tao::pegtl::opt;
using tao::pegtl::parse;
using tao::pegtl::range;
using tao::pegtl::rep;
using tao::pegtl::rep_min_max;
using tao::pegtl::rep_opt;
using tao::pegtl::seq;
using tao::pegtl::sor;
using tao::pegtl::string;
using tao::pegtl::two;

using tao::pegtl::abnf::DIGIT;
using tao::pegtl::abnf::HEXDIG;

#include <glog/logging.h>

namespace IP6 {

using dot   = one<'.'>;
using colon = one<':'>;

// clang-format off
struct dec_octet : sor<seq<string<'2','5'>, range<'0','5'>>,
                       seq<one<'2'>, range<'0','4'>, DIGIT>,
                       seq<range<'0', '1'>, rep<2, DIGIT>>,
                       rep_min_max<1, 2, DIGIT>> {};
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

struct ipv6_address_literal : seq<TAO_PEGTL_ISTRING(lit_pfx),
                                  ipv6_address,
                                  TAO_PEGTL_ISTRING(lit_sfx)> {
};

struct ipv6_address_only : seq<ipv6_address, eof> {
};
struct ipv6_address_literal_only : seq<ipv6_address_literal, eof> {
};

namespace {
bool istarts_with(std::string_view str, std::string_view prefix)
{
  if (str.size() >= prefix.size())
    return iequal(str.substr(0, prefix.size()), prefix);
  return false;
}
} // namespace

bool is_private(std::string_view addr)
{
  CHECK(is_address(addr));

  // <https://en.wikipedia.org/wiki/Private_network#Private_IPv6_addresses>
  return istarts_with(addr, "fd");
}

bool is_address(std::string_view addr)
{
  memory_input<> in{addr.data(), addr.size(), "ip6"};
  return parse<IP6::ipv6_address_only>(in);
}

bool is_address_literal(std::string_view addr)
{
  memory_input<> in{addr.data(), addr.size(), "ip6"};
  return parse<IP6::ipv6_address_literal_only>(in);
}

std::string to_address_literal(std::string_view addr)
{
  CHECK(is_address(addr));
  return fmt::format("{}{}{}", lit_pfx, addr, lit_sfx);
}

std::string reverse(std::string_view addr_str)
{
  in6_addr addr{};

  static_assert(sizeof(addr) == 16, "in6_addr is the wrong size");

  auto const addr_void{reinterpret_cast<void*>(&addr)};
  auto const addr_uint{reinterpret_cast<uint8_t const*>(&addr)};

  CHECK_EQ(1, inet_pton(AF_INET6, addr_str.data(), addr_void));

  auto q{std::string{}};
  q.reserve(2 * NS_IN6ADDRSZ);

  for (auto n{NS_IN6ADDRSZ - 1}; n >= 0; --n) {
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
} // namespace IP6

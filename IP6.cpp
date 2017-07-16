#include "IP6.hpp"

#include "DNS.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

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

struct ipv6_address_literal
    : seq<one<'['>, TAOCPP_PEGTL_ISTRING("IPv6:"), ipv6_address, one<']'>> {
};

bool is_address(std::experimental::string_view addr)
{
  memory_input<> in(addr.data(), addr.size(), "ip6");
  if (parse<IP6::ipv6_address>(in)) {
    return true;
  }
  return false;
}

bool is_address_literal(std::experimental::string_view addr)
{
  memory_input<> in(addr.data(), addr.size(), "ip6");
  if (parse<IP6::ipv6_address_literal>(in)) {
    return true;
  }
  return false;
}

std::string to_address_literal(std::experimental::string_view addr)
{
  return "[IPv6:"s + std::string(addr.data(), addr.size()) + "]"s;
}

std::experimental::string_view to_address(std::experimental::string_view addr)
{
  CHECK(is_address_literal(addr));
  return std::experimental::string_view(addr.begin() + 6, addr.length() - 7);
}

std::string reverse(std::experimental::string_view addr_str)
{
  in6_addr addr;

  static_assert(sizeof(addr) == 16, "in6_addr is the wrong size");

  if (1
      != inet_pton(AF_INET6, addr_str.data(), reinterpret_cast<void*>(&addr))) {
    return "";
  }

  auto uaddr = reinterpret_cast<uint8_t const*>(&addr);

  std::string q;

  for (auto n = NS_IN6ADDRSZ - 1; n >= 0; n--) {
    static const char nibblechar[] = "0123456789abcdef";
    q += nibblechar[uaddr[n] & 0xf];
    q += '.';
    q += nibblechar[(uaddr[n] >> 4) & 0xf];
    q += '.';
  }

  return q;
}

std::string fcrdns(char const* addr)
{
  using namespace DNS;
  Resolver res;

  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto reversed = reverse(addr);

  // The reverse part, check PTR records.
  auto ptrs = get_records<RR_type::PTR>(res, reversed + "ip6.arpa");

  auto ptr = std::find_if(
      ptrs.begin(), ptrs.end(), [&res, addr](std::string const& s) {
        // The forward part, check each PTR for matching AAAA record.
        std::vector<std::string> addrs = get_records<RR_type::AAAA>(res, s);
        return std::find(addrs.begin(), addrs.end(), addr) != addrs.end();
      });

  if (ptr != ptrs.end()) {
    return *ptr;
  }
  return "";
}
}

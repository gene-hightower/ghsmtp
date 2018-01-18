#include "IP4.hpp"

#include "DNS.hpp"

#include <glog/logging.h>

using namespace std::string_literals;

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace IP4 {

using dot = one<'.'>;

// clang-format off
struct dec_octet : sor<rep_min_max<1, 2, DIGIT>,
                       seq<range<'0', '1'>, DIGIT, DIGIT>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<string<'2','5'>, range<'0','5'>>> {};
// clang-format on

struct ipv4_address
  : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet, eof> {
};

struct ipv4_address_lit : seq<one<'['>,
                              dec_octet,
                              dot,
                              dec_octet,
                              dot,
                              dec_octet,
                              dot,
                              dec_octet,
                              one<']'>,
                              eof> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<dec_octet> {
  template <typename Input>
  static void apply(Input const& in, std::vector<std::string>& a)
  {
    a.push_back(in.string());
  }
};

bool is_routable(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "addr"}};
  auto a{std::vector<std::string>{}};
  a.reserve(4);
  auto const ret = parse<ipv4_address, action>(in, a);
  CHECK(ret);

  // From RFC 1918:
  // 10.0.0.0        -   10.255.255.255  (10/8 prefix)
  // 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
  // 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)

  if (a[3] == "10")
    return false;

  if (a[3] == "172") {
    auto oct = atoi(a[2].c_str());
    if ((16 <= oct) && (oct <= 31))
      return false;
    return true;
  }

  if ((a[3] == "192") && (a[2] == "168")) {
    return false;
  }

  return true;
}

bool is_address(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "addr"}};
  return parse<ipv4_address>(in);
}

bool is_address_literal(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "addr"}};
  return parse<ipv4_address_lit>(in);
}

std::string to_address_literal(std::string_view addr)
{
  CHECK(is_address(addr));
  return "["s + std::string(addr.data(), addr.size()) + "]"s;
}

std::string_view to_address(std::string_view addr)
{
  CHECK(is_address_literal(addr));
  return std::string_view(addr.begin() + 1, addr.length() - 2);
}

std::string reverse(std::string_view addr)
{
  auto in{memory_input<>{addr.data(), addr.size(), "addr"}};
  auto a{std::vector<std::string>{}};
  a.reserve(4);
  auto const ret = parse<ipv4_address, action>(in, a);
  CHECK(ret);

  auto reverse{std::ostringstream{}};
  reverse << a[3] << '.' << a[2] << '.' << a[1] << '.' << a[0] << '.';

  return reverse.str();
}

std::string fcrdns(std::string_view addr)
{
  using namespace DNS;

  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto const reversed{reverse(addr)};

  // The reverse part, check PTR records.
  auto res{DNS::Resolver{}};
  auto const ptrs = get_records<RR_type::PTR>(res, reversed + "in-addr.arpa");

  auto const ptr = std::find_if(
      ptrs.begin(), ptrs.end(), [&res, addr](std::string const& s) {
        // The forward part, check each PTR for matching A record.
        auto const addrs = get_records<RR_type::A>(res, s);
        return std::find(addrs.begin(), addrs.end(), addr) != addrs.end();
      });

  if (ptr != ptrs.end()) {
    return *ptr;
  }
  return "";
}
} // namespace IP4

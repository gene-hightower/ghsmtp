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
  static void apply(Input const& in, std::vector<unsigned>& a)
  {
    auto oct = strtoul(in.string().c_str(), nullptr, 10);
    LOG(INFO) << "oct == " << oct;
    a.push_back(oct);
  }
};

bool is_address(std::string_view addr)
{
  memory_input<> in(addr.data(), addr.size(), "addr");
  return parse<ipv4_address>(in);
}

bool is_address_literal(std::string_view addr)
{
  memory_input<> in(addr.data(), addr.size(), "addr");
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
  memory_input<> in(addr.data(), addr.size(), "addr");
  std::vector<unsigned> a;
  a.reserve(4);
  auto ret = parse<ipv4_address, action>(in, a);
  CHECK(ret);

  std::ostringstream reverse;
  reverse << a[3] << '.' << a[2] << '.' << a[1] << '.' << a[0] << '.';

  return reverse.str();
}

std::string fcrdns(char const* addr)
{
  using namespace DNS;

  // <https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS>

  auto reversed = reverse(addr);

  // The reverse part, check PTR records.
  DNS::Resolver res;
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

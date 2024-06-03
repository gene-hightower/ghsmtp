#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <string>
#include <string_view>

#include <glog/logging.h>

namespace IP6 {
using namespace std::literals::string_view_literals;

auto is_private(std::string_view addr) -> bool;
auto is_address(std::string_view addr) -> bool;
auto is_address_literal(std::string_view addr) -> bool;
auto to_address_literal(std::string_view addr) -> std::string;
auto reverse(std::string_view addr) -> std::string;

auto constexpr lit_pfx{"[IPv6:"sv};
auto constexpr lit_pfx_sz{std::size(lit_pfx)};

auto constexpr lit_sfx{"]"sv};
auto constexpr lit_sfx_sz{std::size(lit_sfx)};

auto constexpr lit_extra_sz{lit_pfx_sz + lit_sfx_sz};

auto constexpr loopback_literal{"[IPv6:::1]"};

constexpr auto as_address(std::string_view address_literal) -> std::string_view
{
  CHECK(is_address_literal(address_literal));
  return address_literal.substr(lit_pfx_sz,
                                address_literal.length() - lit_extra_sz);
}

} // namespace IP6

#endif // IP4_DOT_HPP

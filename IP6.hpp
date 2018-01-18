#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <string>
#include <string_view>

namespace IP6 {
auto is_private(std::string_view addr) -> bool;
auto is_address(std::string_view addr) -> bool;
auto is_address_literal(std::string_view addr) -> bool;
auto to_address_literal(std::string_view addr) -> std::string;
auto constexpr as_address(std::string_view addr) -> std::string_view;
auto reverse(std::string_view addr) -> std::string;
auto fcrdns(std::string_view addr) -> std::string;

constexpr char lit_pfx[] = "[IPv6:";
constexpr auto lit_pfx_sz{sizeof(lit_pfx) - 1};

constexpr char lit_sfx[] = "]";
constexpr auto lit_sfx_sz{sizeof(lit_sfx) - 1};

constexpr auto lit_add_sz{lit_pfx_sz + lit_sfx_sz};

auto constexpr as_address(std::string_view addr) -> std::string_view
{
  // CHECK(is_address_literal(addr));
  return std::string_view(addr.begin() + lit_pfx_sz,
                          addr.length() - lit_add_sz);
}

} // namespace IP6

#endif // IP4_DOT_HPP

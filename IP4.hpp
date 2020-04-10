#ifndef IP4_DOT_HPP
#define IP4_DOT_HPP

#include <string>
#include <string_view>
#include <vector>

namespace IP4 {
auto is_private(std::string_view addr) -> bool;
auto is_address(std::string_view addr) -> bool;
auto is_address_literal(std::string_view addr) -> bool;
auto to_address_literal(std::string_view addr) -> std::string;
auto reverse(std::string_view addr) -> std::string;
auto fcrdns(std::string_view addr) -> std::vector<std::string>;

constexpr char lit_pfx[] = "[";
constexpr auto lit_pfx_sz{sizeof(lit_pfx) - 1};

constexpr char lit_sfx[] = "]";
constexpr auto lit_sfx_sz{sizeof(lit_sfx) - 1};

constexpr auto lit_extra_sz{lit_pfx_sz + lit_sfx_sz};

constexpr auto loopback_literal{"[127.0.0.1]"};

constexpr auto as_address(std::string_view address_literal) -> std::string_view
{
  // CHECK(is_address_literal(address_literal));
  return std::string_view(begin(address_literal) + lit_pfx_sz,
                          size(address_literal) - lit_extra_sz);
}

} // namespace IP4

#endif // IP4_DOT_HPP

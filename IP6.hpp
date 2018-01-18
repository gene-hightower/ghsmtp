#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <string>
#include <string_view>

namespace IP6 {
auto is_private(std::string_view addr) -> bool;
auto is_address(std::string_view addr) -> bool;
auto is_address_literal(std::string_view addr) -> bool;
auto to_address_literal(std::string_view addr) -> std::string;
auto as_address(std::string_view addr) -> std::string_view;
auto reverse(std::string_view addr) -> std::string;
auto fcrdns(std::string_view addr) -> std::string;
} // namespace IP6

#endif // IP4_DOT_HPP

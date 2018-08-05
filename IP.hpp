#ifndef IP_DOT_HPP
#define IP_DOT_HPP

#include <string>
#include <string_view>

namespace IP {
bool is_private(std::string_view addr);
bool is_address(std::string_view addr);
bool is_address_literal(std::string_view addr);
std::string to_address_literal(std::string_view addr);
std::string_view as_address(std::string_view addr);
std::string reverse(std::string_view addr);
} // namespace IP

#endif // IP_DOT_HPP

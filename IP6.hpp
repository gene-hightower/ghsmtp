#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <string>
#include <string_view>

namespace IP6 {

bool is_address(std::string_view addr);
bool is_address_literal(std::string_view addr);
std::string to_address_literal(std::string_view addr);
std::string_view to_address(std::string_view addr);
std::string reverse(std::string_view addr);
std::string fcrdns(char const* addr);
}

#endif // IP4_DOT_HPP

#ifndef IP_DOT_HPP
#define IP_DOT_HPP

#include <experimental/string_view>
#include <string>

namespace DNS {
class Resolver;
}

namespace IP {
bool is_address(std::experimental::string_view addr);
bool is_address_literal(std::experimental::string_view addr);
std::string to_address_literal(std::experimental::string_view addr);
std::experimental::string_view to_address(std::experimental::string_view addr);
std::string reverse(std::experimental::string_view addr);
std::string fcrdns(DNS::Resolver& res, char const* addr);
}

#endif // IP_DOT_HPP

#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <experimental/string_view>

#include <glog/logging.h>

namespace IP6 {

bool is_address(std::experimental::string_view addr);
bool is_address_literal(std::experimental::string_view addr);
std::string reverse(std::experimental::string_view addr);
}

#endif // IP4_DOT_HPP

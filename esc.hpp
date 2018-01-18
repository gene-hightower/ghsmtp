#ifndef ESC_DOT_HPP
#define ESC_DOT_HPP

#include <string>
#include <string_view>

auto esc(std::string_view str, bool multi_line = false) -> std::string;

#endif // ESC_DOT_HPP

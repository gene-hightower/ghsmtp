#ifndef ESC_DOT_HPP
#define ESC_DOT_HPP

#include <string>
#include <string_view>

enum class esc_line_option : bool { single, multi };
std::string esc(std::string_view str,
                esc_line_option  line_option = esc_line_option::single);

#endif // ESC_DOT_HPP

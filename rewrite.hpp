#ifndef REWRITE_DOT_HPP_INCLUDED
#define REWRITE_DOT_HPP_INCLUDED

#include <optional>
#include <string>
#include <string_view>

std::optional<std::string> rewrite(char const* domain, std::string_view input);

#endif // REWRITE_DOT_HPP_INCLUDED

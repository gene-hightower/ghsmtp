#include "esc.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <iomanip>
#include <sstream>

std::string esc(std::string_view str, esc_line_option line_option)
{
  auto nesc{std::count_if(begin(str), end(str), [](unsigned char c) {
    return (!std::isprint(c)) || (c == '\\');
  })};
  if (!nesc)
    return std::string(str);
  if (line_option == esc_line_option::multi)
    nesc += std::count(begin(str), end(str), '\n');
  std::string ret;
  ret.reserve(str.length() + nesc);
  for (auto c : str) {
    switch (c) {
    case '\a':
      ret += "\\a";
      break;
    case '\b':
      ret += "\\b";
      break;
    case '\f':
      ret += "\\f";
      break;
    case '\n':
      ret += "\\n";
      if (line_option == esc_line_option::multi)
        ret += '\n';
      break;
    case '\r':
      ret += "\\r";
      break;
    case '\t':
      ret += "\\t";
      break;
    case '\v':
      ret += "\\v";
      break;
    case '\\':
      ret += "\\\\";
      break;
    default:
      if (isprint(static_cast<unsigned char>(c))) {
        ret += c;
      }
      else {
        ret += fmt::format("\\x{:02x}", static_cast<unsigned char>(c));
      }
    }
  }
  if (line_option == esc_line_option::multi) {
    auto length = ret.length();
    if (length && ('\n' == ret.at(length - 1))) {
      ret.erase(length - 1, 1);
    }
  }
  return ret;
}

#include "esc.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <iomanip>
#include <sstream>

using namespace std::string_literals;

std::string esc(std::string_view str, esc_line_option line_option)
{
  auto nesc{std::count_if(str.begin(), str.end(), [](unsigned char c) {
    return (!std::isprint(c)) || (c == '\\');
  })};
  if (!nesc)
    return std::string(str);
  if (line_option == esc_line_option::multi)
    nesc += std::count(str.begin(), str.end(), '\n');
  std::string ret;
  ret.reserve(str.length() + nesc);
  for (auto c : str) {
    switch (c) {
    case '\a':
      ret += "\\a"s;
      break;
    case '\b':
      ret += "\\b"s;
      break;
    case '\f':
      ret += "\\f"s;
      break;
    case '\n':
      ret += "\\n"s;
      if (line_option == esc_line_option::multi)
        ret += '\n';
      break;
    case '\r':
      ret += "\\r"s;
      break;
    case '\t':
      ret += "\\t"s;
      break;
    case '\v':
      ret += "\\v"s;
      break;
    case '\\':
      ret += "\\\\"s;
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

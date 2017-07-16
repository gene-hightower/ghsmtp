#include "esc.hpp"

using std::experimental::string_view;

using namespace std::string_literals;

std::string esc(string_view str)
{
  std::string ret;
  for (auto c : str) {
    switch (c) {
    case '\\':
      ret += "\\\\"s;
      break;
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
      break;
    case '\r':
      ret += "\\r"s;
      break;
    case '\t':
      ret += "\\t"s;
      break;
    case '\'':
      ret += "\'"s;
      break;
    default:
      ret += c;
    }
  }
  return ret;
}

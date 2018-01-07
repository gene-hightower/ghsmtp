#include "esc.hpp"

#include <iomanip>
#include <sstream>

using namespace std::string_literals;

std::string esc(std::string_view str)
{
  std::string ret;
  ret.reserve(str.length() + 2);
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
        std::stringstream ss;
        ss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(static_cast<unsigned char>(c));
        ret += ss.str();
      }
    }
  }
  return ret;
}

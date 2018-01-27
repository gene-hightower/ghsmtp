#ifndef IEQUAL_DOT_HPP
#define IEQUAL_DOT_HPP

#include <cctype>
#include <string_view>

// Like boost, but ASCII only.  No locale required.

inline bool iequal_char(char a, char b)
{
  return std::toupper(static_cast<unsigned char>(a))
         == std::toupper(static_cast<unsigned char>(b));
}

inline bool iequal(std::string_view a, std::string_view b)
{
  if (a.length() == b.length()) {
    return std::equal(b.begin(), b.end(), a.begin(), iequal_char);
  }
  return false;
}

#endif // IEQUAL_DOT_HPP

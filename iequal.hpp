#ifndef IEQUAL_DOT_HPP
#define IEQUAL_DOT_HPP

#include <algorithm>
#include <cctype>
#include <string_view>

// Like boost, but ASCII only.  Only C locale required.

inline bool iequal_char(char a, char b)
{
  return std::toupper(static_cast<unsigned char>(a)) ==
         std::toupper(static_cast<unsigned char>(b));
}

inline bool iequal(std::string_view a, std::string_view b)
{
  return (size(a) == size(b)) &&
         std::equal(begin(b), end(b), begin(a), iequal_char);
}

inline bool iless_char(char a, char b)
{
  return std::toupper(static_cast<unsigned char>(a)) <
         std::toupper(static_cast<unsigned char>(b));
}

inline bool iless(std::string_view a, std::string_view b)
{
  return std::lexicographical_compare(begin(a), end(a), begin(b), end(b),
                                      iless_char);
}

inline bool istarts_with(std::string_view str, std::string_view prefix)
{
  return (str.size() >= prefix.size()) &&
         iequal(str.substr(0, prefix.size()), prefix);
}

struct ci_less {
  bool operator()(std::string_view a, std::string_view b) const
  {
    return iless(a, b);
  }
};

// Ahh, the olden days of loops and pointers...

// inline bool iequal(char const* a, char const* b)
// {
//   if (a == b)
//     return true;
//   for (;;) {
//     if (!iequal_char(*a, *b))
//       return false;
//     if (*a == '\0')
//       return true;
//     ++a;
//     ++b;
//   }
// }

#endif // IEQUAL_DOT_HPP

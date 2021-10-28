#include <algorithm>
#include <string_view>

constexpr bool isascii(auto c) noexcept
{
  return (static_cast<unsigned char>(c) & 0x80) == 0;
}

constexpr bool is_ascii(std::string_view str) noexcept
{
  // return !std::any_of(std::begin(str), std::end(str),
  //                     [](auto ch) { return !isascii(ch); });
  for (auto ch : str) {
    if (!isascii(ch))
      return false;
  }
  return true;
}

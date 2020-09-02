#include "rewrite.hpp"

#include <cstring>

std::pair<std::unique_ptr<char[]>, size_t> rewrite(char const* dp_in,
                                                   size_t      length_in)
{
  // Dummy re-write for now...
  auto dp = std::make_unique<char[]>(length_in);
  std::memcpy(dp.get(), dp_in, length_in);
  return std::pair{std::move(dp), length_in};
}

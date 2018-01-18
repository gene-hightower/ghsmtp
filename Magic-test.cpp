#include "Magic.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

int main(int argc, char* argv[])
{
  auto magic{Magic{}};

  auto width = 0ul;
  for (auto arg = 1; arg < argc; ++arg) {
    auto const idx = arg - 1;
    auto const len = strlen(argv[idx]);
    width = std::max(width, len);
  }

  for (auto arg = 1; arg < argc; ++arg) {
    std::cout << std::setw(width) << argv[arg] << ": " << magic.file(argv[arg])
              << '\n';
  }
}

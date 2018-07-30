#include "Magic.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

int main(int argc, char* argv[])
{
  auto width = 0ul;
  for (auto arg = 1; arg < argc; ++arg) {
    auto const len = strlen(argv[arg]);
    width = std::max(width, len);
  }

  Magic magic;
  for (auto arg = 1; arg < argc; ++arg) {
    std::cout << std::setw(width) << argv[arg] << ": " << magic.file(argv[arg])
              << '\n';
  }
}

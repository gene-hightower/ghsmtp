#include "Magic.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

int main(int argc, char* argv[])
{
  Magic magic;

  size_t width = 0;
  for (auto arg = 1; arg < argc; ++arg) {
    auto idx = arg - 1;
    auto len = strlen(argv[idx]);
    width = std::max(width, len);
  }

  for (auto arg = 1; arg < argc; ++arg) {
    auto idx = arg - 1;
    std::cout << std::setw(width) << argv[idx] << ": " << magic.file(argv[idx])
              << '\n';
  }
}

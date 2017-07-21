#include "Magic.hpp"

#include <iostream>
#include <string>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  Magic magic;

  std::vector<std::string> results;

  for (auto arg=1; arg<argc; ++arg) {
    results.push_back(magic.file(argv[arg]));
  }

  for (auto arg=1; arg<argc; ++arg) {
    std::cout << results[arg-1] << '\n';
  }
}

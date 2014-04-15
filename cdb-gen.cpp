#include <iostream>
#include <string>

int main(int argc, char const* argv[])
{
  std::string line;
  while (std::getline(std::cin, line)) {
    std::cout << "+" << line.length() << ",1:" << line << "->1" << std::endl;
  }
  std::cout << std::endl;
}

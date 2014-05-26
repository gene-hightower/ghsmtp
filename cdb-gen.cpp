#include <iostream>
#include <string>

int main(int argc, char const* argv[])
{
  std::string line;
  while (std::getline(std::cin, line)) {

    /* From cdb(1) man page, section Input/Output Format:
        +klen,vlen:key->val\n
    */
    std::cout << "+" << line.length() << ",1:" << line << "->1\n";
  }
  std::cout << std::endl;
}

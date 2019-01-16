#include "Now.hpp"

#include <iostream>

int main(int argc, char* argv[])
{
  Now then;

  std::cout << "sizeof(Now) == " << sizeof(Now) << '\n';

  std::stringstream then_str;
  then_str << then;

  Now then_again{then};
  std::stringstream then_again_str;
  then_again_str << then_again;

  CHECK_EQ(then_str.str(), then_again_str.str());
}

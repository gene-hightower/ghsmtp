#include "Pill.hpp"

#include <iostream>
#include <string.h>

int main(int arcv, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Pill red, blue;
  CHECK(red != blue);

  std::stringstream red_str, blue_str;

  red_str << red;
  blue_str << blue;

  CHECK_NE(red_str.str(), blue_str.str());

  CHECK_EQ(13U, red_str.str().length());
  CHECK_EQ(13U, blue_str.str().length());

  Pill red2(red);
  CHECK_EQ(red, red2);

  std::cout << "sizeof(Pill) == " << sizeof(Pill) << '\n';
  std::cout << red << '\n' << blue << '\n';
}

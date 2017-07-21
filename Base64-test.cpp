#include "Base64.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  constexpr char const* text = R"(
“We are all in the gutter, but some of us are looking at the stars.”
                                                     ― Oscar Wilde
)";

  CHECK_EQ(Base64::dec(Base64::enc(text)), text);

  std::string s = text;

  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);

  constexpr char const* empty = "";
  CHECK_EQ(Base64::dec(Base64::enc(empty)), empty);
}

#include "esc.hpp"

#include <iostream>
#include <string>

#include <glog/logging.h>

using namespace std::string_literals;

int main()
{
  std::string s0;
  s0 += '\a';
  s0 += '\xa0';
  s0 += '\b';
  s0 += '\t';
  s0 += '\n';
  s0 += '\v';
  s0 += '\f';
  s0 += '\r';
  s0 += '\\';
  auto escaped0 = esc(s0);
  CHECK_EQ(escaped0, "\\a\\xa0\\b\\t\\n\\v\\f\\r\\\\"s);

  auto s1 = "not escaped at all"s;
  CHECK_EQ(esc(s1), s1);
}

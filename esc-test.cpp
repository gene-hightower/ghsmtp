#include "esc.hpp"

#include <iostream>
#include <string>

#include <glog/logging.h>

using namespace std::string_literals;

int main()
{
  std::string s;
  s += '\a';
  s += '\xa0';
  s += '\b';
  s += '\t';
  s += '\n';
  s += '\v';
  s += '\f';
  s += '\r';
  s += '\\';
  auto escaped = esc(s);
  CHECK_EQ(escaped, "\\a\\xa0\\b\\t\\n\\v\\f\\r\\\\"s);
}

#include "iequal.hpp"

#include <string>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  CHECK(iequal("", ""));
  CHECK(!iequal("a", ""));
  CHECK(!iequal("", "b"));

  CHECK(iequal("string", "StRiNg"));
  CHECK(!iequal("NOT string", "string"));

  CHECK(istarts_with("FooBarBaz", "foo"));
  CHECK(iends_with("FooBarBaz", "baz"));

  CHECK(istarts_with("foo", "Foo"));
  CHECK(iends_with("Bar", "bar"));

  CHECK(!istarts_with("foo", "foobarbaz"));
  CHECK(!iends_with("FooBarBaz", "bbaz"));
}

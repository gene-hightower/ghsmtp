#include "Domain.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  std::string d{"example.com."};

  CHECK(Domain::match(d, "EXAMPLE.COM"));
  CHECK(Domain::match(d, "example.com"));
  CHECK(Domain::match(d, "example.com."));

  CHECK(!Domain::match(d, "example.co"));
  CHECK(!Domain::match(d, "example.com.."));
  CHECK(!Domain::match(d, ""));
  CHECK(!Domain::match(d, "."));

  std::string d2{"example.com"};

  CHECK(Domain::match(d2, "EXAMPLE.COM"));
  CHECK(Domain::match(d2, "example.com"));
  CHECK(Domain::match(d2, "example.com."));

  CHECK(!Domain::match(d2, "example.co"));
  CHECK(!Domain::match(d2, "example.com.."));
  CHECK(!Domain::match(d2, ""));
  CHECK(!Domain::match(d2, "."));

  std::string d3{""};

  CHECK(Domain::match(d3, ""));
  CHECK(Domain::match(d3, "."));

  CHECK(!Domain::match(d3, "example.com"));
}

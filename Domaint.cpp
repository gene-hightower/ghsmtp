#include "Domain.hpp"

#include "Logging.hpp"

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  std::string d{ "digilicious.com." };

  CHECK(Domain::match(d, "DIGILICIOUS.COM"));
  CHECK(Domain::match(d, "digilicious.com"));
  CHECK(Domain::match(d, "digilicious.com."));

  CHECK(!Domain::match(d, "digilicious.co"));
  CHECK(!Domain::match(d, "digilicious.com.."));
}

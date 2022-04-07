#include "TLD.hpp"

#include <iostream>

int main(int argc, char const* argv[])
{
  TLD tld;

  CHECK_NOTNULL(tld.get_registered_domain("digilicious.com"));
  CHECK_NOTNULL(tld.get_registered_domain("yahoo.com"));
  CHECK_NOTNULL(tld.get_registered_domain("google.com"));

  CHECK_NOTNULL(tld.get_registered_domain("foo.blogspot.com.ar"));

  CHECK_EQ(strcmp(tld.get_registered_domain("pi.digilicious.com"),
                  "digilicious.com"),
           0);

  CHECK_EQ(strcmp(tld.get_registered_domain("outmail14.phi.meetup.com"),
                  "meetup.com"),
           0);

  CHECK(nullptr == tld.get_registered_domain("not_a_domain_at_all"));
  CHECK(nullptr == tld.get_registered_domain(".com"));
  CHECK(nullptr == tld.get_registered_domain("."));

  CHECK_EQ(strcmp(tld.get_registered_domain("reward.yournewestbonuspoints.com"),
                  "yournewestbonuspoints.com"),
           0);
}

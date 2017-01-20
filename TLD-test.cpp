/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
*/

#include "TLD.hpp"

#include <iostream>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  TLD tld;

  CHECK_NOTNULL(tld.get_registered_domain("digilicious.com"));
  CHECK_NOTNULL(tld.get_registered_domain("yahoo.com"));
  CHECK_NOTNULL(tld.get_registered_domain("google.com"));

  CHECK(!strcmp(tld.get_registered_domain("pi.digilicious.com"),
                "digilicious.com"));

  CHECK(!strcmp(tld.get_registered_domain("outmail14.phi.meetup.com"),
                "meetup.com"));

  CHECK(nullptr == tld.get_registered_domain("not_a_domain_at_all"));
  CHECK(nullptr == tld.get_registered_domain(".com"));
  CHECK(nullptr == tld.get_registered_domain("."));

  CHECK(!strcmp(tld.get_registered_domain("reward.yournewestbonuspoints.com"),
                "yournewestbonuspoints.com"));
}

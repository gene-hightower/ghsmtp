/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "TLD.hpp"

#include <iostream>

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  TLD tld;

  CHECK_NOTNULL(tld.get_registered_domain("digilicious.com"));
  CHECK_NOTNULL(tld.get_registered_domain("yahoo.com"));
  CHECK_NOTNULL(tld.get_registered_domain("google.com"));

  CHECK(!strcmp(tld.get_registered_domain("pi.digilicious.com"),
                "digilicious.com"));

  CHECK(nullptr == tld.get_registered_domain("not_a_domain_at_all"));
  CHECK(nullptr == tld.get_registered_domain(".com"));
  CHECK(nullptr == tld.get_registered_domain("."));
}

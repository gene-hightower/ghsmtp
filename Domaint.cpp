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

#include "Domain.hpp"

#include "Logging.hpp"

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  std::string d{ "example.com." };

  CHECK(Domain::match(d, "EXAMPLE.COM"));
  CHECK(Domain::match(d, "example.com"));
  CHECK(Domain::match(d, "example.com."));

  CHECK(!Domain::match(d, "example.co"));
  CHECK(!Domain::match(d, "example.com.."));
  CHECK(!Domain::match(d, ""));
  CHECK(!Domain::match(d, "."));

  std::string d2{ "example.com" };

  CHECK(Domain::match(d2, "EXAMPLE.COM"));
  CHECK(Domain::match(d2, "example.com"));
  CHECK(Domain::match(d2, "example.com."));

  CHECK(!Domain::match(d2, "example.co"));
  CHECK(!Domain::match(d2, "example.com.."));
  CHECK(!Domain::match(d2, ""));
  CHECK(!Domain::match(d2, "."));

  std::string d3{ "" };

  CHECK(Domain::match(d3, ""));
  CHECK(Domain::match(d3, "."));

  CHECK(!Domain::match(d3, "example.com"));
}

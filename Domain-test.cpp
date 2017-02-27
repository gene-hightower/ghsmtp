/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

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

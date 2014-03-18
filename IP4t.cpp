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

#include "IP4.hpp"

#include "Logging.hpp"

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  CHECK(IP4::is_address("127.0.0.1"));
  CHECK(!IP4::is_address("127.0.0.1."));
  CHECK(!IP4::is_address("foo.bar"));
  CHECK(!IP4::is_address(""));

  // Limitation of my regex
  //CHECK(!IP4::is_address("300.300.300.300"));

  std::string reverse { IP4::reverse("127.0.0.1") };
  CHECK_EQ(0, reverse.compare("1.0.0.127."));
}

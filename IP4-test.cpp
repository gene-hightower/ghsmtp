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

#include "IP4.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK(IP4::is_bracket_address("[69.0.0.0]"));
  CHECK(!IP4::is_bracket_address("69.0.0.0]"));
  CHECK(!IP4::is_bracket_address("[69.0.0.0"));
  CHECK(!IP4::is_bracket_address("[]"));
  CHECK(!IP4::is_bracket_address("[1234]"));

  CHECK(IP4::is_address("69.0.0.0"));
  CHECK(IP4::is_address("160.0.0.0"));
  CHECK(IP4::is_address("250.0.0.0"));
  CHECK(IP4::is_address("251.0.0.0"));
  CHECK(IP4::is_address("252.0.0.0"));
  CHECK(IP4::is_address("253.0.0.0"));
  CHECK(IP4::is_address("254.0.0.0"));
  CHECK(IP4::is_address("111.0.0.0"));

  CHECK(IP4::is_address("9.9.9.9"));
  CHECK(IP4::is_address("99.99.99.99"));
  CHECK(IP4::is_address("255.0.0.1"));
  CHECK(IP4::is_address("127.0.0.1"));

  CHECK(!IP4::is_address("127.0.0.1."));
  CHECK(!IP4::is_address("foo.bar"));
  CHECK(!IP4::is_address(""));

  // If this is acceptable,
  CHECK(IP4::is_address("001.0.0.0"));
  // why not:
  CHECK(!IP4::is_address("0001.0.0.0"));
  // or:
  CHECK(!IP4::is_address("00001.0.0.0"));
  // ?

  // Many RFCs (see <https://tools.ietf.org/html/rfc3795>) talk about a
  // 3DIGIT, but I can't seem to locate a definition for that.

  CHECK(!IP4::is_address("256.0.0.0"));
  CHECK(!IP4::is_address("260.0.0.0"));
  CHECK(!IP4::is_address("300.0.0.0"));
  CHECK(!IP4::is_address("1000.0.0.0"));

  std::string reverse{IP4::reverse("1.2.3.4")};
  CHECK_EQ(0, reverse.compare("4.3.2.1."));
}

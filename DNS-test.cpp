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

#include "DNS.hpp"

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK_EQ(sizeof(DNS::Resolver), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Domain), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Query<DNS::RR_type::A>), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Rrlist<DNS::RR_type::A>), sizeof(void*));

  DNS::Resolver res;
  std::vector<std::string> addrs
      = DNS::get_records<DNS::RR_type::A>(res, "digilicious.com");

  CHECK_EQ(addrs.size(), 1U);
  CHECK_EQ(addrs[0], "108.83.36.113");
}

/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

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

#include "DNS.hpp"

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  CHECK_EQ(sizeof(DNS::Resolver), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Domain), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Query<DNS::RR_type::A>), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Rrlist<DNS::RR_type::A>), sizeof(void*));
}

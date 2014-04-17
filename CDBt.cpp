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

#include "CDB.hpp"

#include "Logging.hpp"

#include <iostream>

int main(int argc, char* argv[])
{
  Logging::init(argv[0]);

  char const* db_2{ "two-level-tlds" };

  CHECK(CDB::lookup(db_2, "0.bg"));
  CHECK(CDB::lookup(db_2, "zzux.com"));
  CHECK(!CDB::lookup(db_2, "This should not be found."));

  char const* db_3{ "three-level-tlds" };

  CHECK(CDB::lookup(db_3, "act.edu.au"));
  CHECK(CDB::lookup(db_3, "zen.co.uk"));
  CHECK(!CDB::lookup(db_3, "This should not be found."));
}

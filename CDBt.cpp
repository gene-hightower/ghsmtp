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

  CDB cdb("two-level-tlds");

  CHECK(cdb.lookup("0.bg"));
  CHECK(cdb.lookup("zzux.com"));
  CHECK(!cdb.lookup("This should not be found."));

  CDB cdb2("three-level-tlds");

  CHECK(cdb2.lookup("act.edu.au"));
  CHECK(cdb2.lookup("zen.co.uk"));
  CHECK(!cdb2.lookup("This should not be found."));
}

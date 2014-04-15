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

#include "stringify.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern "C" {
#include <cdb.h>
}

namespace CDB {

bool lookup(std::string const& db, std::string const& key)
{
  std::string dbpath = STRINGIFY(SMTP_HOME) "/" + db + ".cdb";

  struct cdb cdb;
  int fd = open(dbpath.c_str(), O_RDONLY);
  PCHECK(fd >= 0) << " can't open " << dbpath;
  cdb_init(&cdb, fd);
  if (cdb_find(&cdb, key.c_str(), key.length()) > 0) {
    close(fd);
    return true;
  }
  close(fd);
  return false;
}
}

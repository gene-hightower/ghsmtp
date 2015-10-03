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

#ifndef CDB_DOT_H
#define CDB_DOT_H

extern "C" {
#include <cdb.h>
}

#include <glog/logging.h>

#include "stringify.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

class CDB {
public:
  CDB(char const* db)
  {
    std::string dbpath = STRINGIFY(SMTP_HOME) "/";
    dbpath += db;
    dbpath += ".cdb";

    fd_ = open(dbpath.c_str(), O_RDONLY);
    PCHECK(fd_ >= 0) << " can't open " << dbpath;
    cdb_init(&cdb_, fd_);
  }
  ~CDB()
  {
    close(fd_);
    cdb_free(&cdb_);
  }
  bool lookup(char const* key)
  {
    if (cdb_find(&cdb_, key, strlen(key)) > 0) {
      return true;
    }
    return false;
  }

private:
  int fd_;
  struct cdb cdb_;
};

#endif // CDB_DOT_H

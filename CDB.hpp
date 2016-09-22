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

#ifndef CDB_DOT_HPP
#define CDB_DOT_HPP

extern "C" {
#include <cdb.h>
}

#include <experimental/string_view>

#include <glog/logging.h>

#include "stringify.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

class CDB {
public:
  CDB(std::experimental::string_view db)
  {
    std::string dbpath = STRINGIFY(SMTP_HOME) "/";
    dbpath.append(db.begin(), db.end());
    dbpath.append(".cdb");

    fd_ = open(dbpath.c_str(), O_RDONLY);
    PCHECK(fd_ >= 0) << " can't open " << dbpath;
    cdb_init(&cdb_, fd_);
  }
  ~CDB()
  {
    close(fd_);
    cdb_free(&cdb_);
  }
  bool lookup(std::experimental::string_view key)
  {
    if (cdb_find(&cdb_, key.data(), key.length()) > 0) {
      return true;
    }
    return false;
  }

private:
  int fd_;
  struct cdb cdb_;
};

#endif // CDB_DOT_HPP

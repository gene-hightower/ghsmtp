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
    CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
    if (cdb_find(&cdb_, key.data(), static_cast<unsigned int>(key.length()))
        > 0) {
      return true;
    }
    return false;
  }

private:
  int fd_;
  struct cdb cdb_;
};

#endif // CDB_DOT_HPP

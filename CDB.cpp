#include "CDB.hpp"

extern "C" {
#include <cdb.h>
}

#include <glog/logging.h>

#include "stringify.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

CDB::CDB(std::string_view db)
{
  std::string dbpath = STRINGIFY(SMTP_HOME) "/";
  dbpath.append(db.begin(), db.end());
  dbpath.append(".cdb");

  fd_ = open(dbpath.c_str(), O_RDONLY);
  if (fd_ == -1) {
    char err[256];
    strerror_r(errno, err, sizeof(err));
    LOG(WARNING) << "unable to open " << dbpath << ": " << err;
  }
  else {
    cdb_ = std::make_unique<struct cdb>();
    cdb_init(cdb_.get(), fd_);
  }
}

CDB::~CDB()
{
  if (fd_ != -1) {
    close(fd_);
    cdb_free(cdb_.get());
  }
}

bool CDB::lookup(std::string_view key)
{
  if (fd_ == -1)
    return false;
  CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
  if (cdb_find(cdb_.get(), key.data(), static_cast<unsigned int>(key.length()))
      > 0) {
    return true;
  }
  return false;
}

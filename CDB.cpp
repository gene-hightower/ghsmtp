#include "CDB.hpp"

#include <glog/logging.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

CDB::CDB(std::string_view db)
{
  std::string db_fn;
  db_fn.append(db.begin(), db.end());
  db_fn.append(".cdb");

  fd_ = ::open(db_fn.c_str(), O_RDONLY);
  if (fd_ == -1) {
    char err[256];
    strerror_r(errno, err, sizeof(err));
    LOG(WARNING) << "unable to open " << db_fn << ": " << err;
  }
  else {
    cdb_init(&cdb_, fd_);
  }
}

CDB::~CDB()
{
  if (fd_ != -1) {
    close(fd_);
    cdb_free(&cdb_);
  }
}

bool CDB::lookup(std::string_view key)
{
  if (fd_ == -1)
    return false;
  CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
  if (cdb_find(&cdb_, key.data(), static_cast<unsigned int>(key.length()))
      > 0) {
    return true;
  }
  return false;
}

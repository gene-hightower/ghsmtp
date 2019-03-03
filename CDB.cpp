#include "CDB.hpp"

#include "fs.hpp"

#include <glog/logging.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

CDB::~CDB()
{
  if (is_open()) {
    close(fd_);
    cdb_free(&cdb_);
  }
}

bool CDB::open(std::string_view db)
{
  fs::path db_path = db;
  db_path += ".cdb";
  auto const db_fn = db_path.string();

  fd_ = ::open(db_fn.c_str(), O_RDONLY);
  if (fd_ == -1) {
    char       err[256]{};
    auto const msg = strerror_r(errno, err, sizeof(err));
    LOG(WARNING) << "unable to open " << db_fn << ": " << msg;
    return false;
  }
  cdb_init(&cdb_, fd_);
  return true;
}

bool CDB::lookup(std::string_view key)
{
  if (!is_open())
    return false;

  CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
  return cdb_find(&cdb_, key.data(), static_cast<unsigned int>(key.length()))
         > 0;
}

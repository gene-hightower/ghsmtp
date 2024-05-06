#include "CDB.hpp"

#include <algorithm> 

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

bool CDB::open(fs::path db_path)
{
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

std::optional<std::string> CDB::find(std::string_view key)
{
  if (!is_open())
    return {};

  CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
  if (cdb_find(&cdb_, key.data(), static_cast<unsigned int>(key.length())) >
      0) {
    auto const  vpos = cdb_datapos(&cdb_);
    auto const  vlen = cdb_datalen(&cdb_);
    std::string val;
    val.resize(vlen);
    cdb_read(&cdb_, &val[0], vlen, vpos);
    return val;
  }

  return {};
}

// No locale, ASCII only.
bool CDB::contains_lc(std::string_view key)
{
  std::string key_lc{key.begin(), key.end()};
  std::transform(key_lc.begin(), key_lc.end(), key_lc.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return contains(key_lc);
}

bool CDB::contains(std::string_view key)
{
  if (!is_open())
    return false;

  CHECK_LT(key.length(), std::numeric_limits<unsigned int>::max());
  return cdb_find(&cdb_, key.data(), static_cast<unsigned int>(key.length())) >
         0;
}

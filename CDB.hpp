#ifndef CDB_DOT_HPP
#define CDB_DOT_HPP

#include <memory>
#include <string_view>

extern "C" {
#include <cdb.h>
}

#include "fs.hpp"

class CDB {
public:
  CDB(CDB const&) = delete;
  CDB& operator=(CDB const&) = delete;

  CDB() = default;
  explicit CDB(std::string_view db) { open(db); }
  explicit CDB(fs::path db) { open(db.c_str()); }
  ~CDB();

  bool           open(std::string_view db);
  bool           lookup(std::string_view key);
  constexpr bool is_open() const;

private:
  int fd_{-1};
  cdb cdb_{0};
};

constexpr bool CDB::is_open() const { return fd_ != -1; }

#endif // CDB_DOT_HPP

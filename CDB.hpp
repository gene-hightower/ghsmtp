#ifndef CDB_DOT_HPP
#define CDB_DOT_HPP

#include <memory>
#include <string_view>

extern "C" {
#include <cdb.h>
}

class CDB {
public:
  CDB(CDB const&) = delete;
  CDB& operator=(CDB const&) = delete;

  CDB() = default;
  explicit CDB(std::string_view db);
  ~CDB();

  bool           open(std::string_view db);
  bool           lookup(std::string_view key);
  constexpr bool is_open() const;

private:
  int        fd_{-1};
  struct cdb cdb_;
};

constexpr bool CDB::is_open() const { return fd_ != -1; }

#endif // CDB_DOT_HPP

#ifndef CDB_DOT_HPP
#define CDB_DOT_HPP

#include <memory>
#include <string_view>

extern "C" {
#include <cdb.h>
}

class CDB {
public:
  CDB(std::string_view db);
  ~CDB();

  auto lookup(std::string_view key) -> bool;
  auto constexpr is_open() const -> bool;

private:
  int fd_{-1};
  struct cdb cdb_;
};

auto constexpr CDB::is_open() const -> bool { return fd_ != -1; }

#endif // CDB_DOT_HPP

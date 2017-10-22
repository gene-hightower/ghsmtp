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
  bool lookup(std::string_view key);

private:
  int fd_{-1};
  struct cdb cdb_;
};

#endif // CDB_DOT_HPP

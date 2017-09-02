#ifndef CDB_DOT_HPP
#define CDB_DOT_HPP

#include <memory>
#include <string_view>

struct cdb;

class CDB {
public:
  CDB(std::string_view db);
  ~CDB();
  bool lookup(std::string_view key);

private:
  int fd_{-1};
  std::unique_ptr<struct cdb> cdb_;
};

#endif // CDB_DOT_HPP

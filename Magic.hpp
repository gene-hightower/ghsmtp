#ifndef MAGIC_DOT_HPP
#define MAGIC_DOT_HPP

#include <string>
#include <string_view>

struct magic_set;

class Magic {
public:
  Magic(Magic const&) = delete;
  Magic operator=(Magic const&) = delete;

  Magic();
  ~Magic();

  std::string buffer(std::string_view bfr) const;
  std::string file(char const* path) const;

private:
  magic_set* magic_; // This library is *not* thread safe!
};

#endif // MAGIC_DOT_HPP

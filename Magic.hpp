#ifndef MAGIC_DOT_HPP
#define MAGIC_DOT_HPP

#include <string>

#include <experimental/string_view>

typedef struct magic_set* magic_t;

class Magic {
public:
  Magic();
  ~Magic();

  std::string buffer(std::experimental::string_view bfr) const;
  std::string file(char const* path) const;

private:
  magic_t magic_;               // This library is *not* thread safe!
};

#endif // MAGIC_DOT_HPP

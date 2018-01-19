#ifndef MAGIC_DOT_HPP
#define MAGIC_DOT_HPP

#include <string>
#include <string_view>

typedef struct magic_set* magic_t;

class Magic {
public:
  Magic(Magic const&) = delete;
  Magic operator=(Magic const&) = delete;

  Magic();
  ~Magic();

  auto buffer(std::string_view bfr) const -> std::string;
  auto file(char const* path) const -> std::string;

private:
  magic_t magic_; // This library is *not* thread safe!
};

#endif // MAGIC_DOT_HPP

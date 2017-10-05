#ifndef IMEMSTREAM_DOT_HPP
#define IMEMSTREAM_DOT_HPP

#include <istream>
#include <streambuf>
#include <string_view>

struct membuf : std::streambuf {
  membuf(char const* base, size_t size)
  {
    auto p = const_cast<char*>(base);
    this->setg(p, p, p + size);
  }
};

struct imemstream : virtual membuf, std::istream {
  imemstream(char const* base, size_t size)
    : membuf(base, size)
    , std::istream(static_cast<std::streambuf*>(this))
  {
  }
  imemstream(std::string_view s)
    : membuf(s.data(), s.length())
    , std::istream(static_cast<std::streambuf*>(this))
  {
  }
};

#endif // IMEMSTREAM_DOT_HPP

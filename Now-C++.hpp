// This version of Now added 103040 bytes of text (code) and 488 bytes
// of data to my smtp program vs. the old school C/Unix style code in
// the version I'm using.  Plus, it's dynamic memory for the string,
// etc.  It seems to just call the same strftime from libc anyhow.
//
// This on x86_64 using gcc version 7.1.1.

#ifndef NOW_DOT_HPP
#define NOW_DOT_HPP

#include <chrono>
#include <iostream>

#include <glog/logging.h>

#include "date/tz.h"

class Now {
public:
  Now()
    : v_{std::chrono::system_clock::now()}
    , str_{
          // RFC 5322 section 3.3 date-time.
          date::format("%a, %d %b %Y %H:%M:%S %z",
                       date::make_zoned(date::current_zone(),
                                        date::floor<std::chrono::seconds>(v_)))}
  {
    CHECK_EQ(str_.length(), 31) << str_ << " is the wrong length";
  }

  auto sec() const
  {
    return std::chrono::duration_cast<std::chrono::seconds>(
               v_.time_since_epoch())
        .count();
  }
  auto usec() const
  {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               v_.time_since_epoch())
        .count();
  }

  std::string const& string() const { return str_; }

  bool operator==(Now const& that) const { return v_ == that.v_; }
  bool operator!=(Now const& that) const { return !(*this == that); }

private:
  std::chrono::time_point<std::chrono::system_clock> v_;
  std::string str_;

  friend std::ostream& operator<<(std::ostream& s, Now const& now)
  {
    return s << now.str_;
  }
};

#endif // NOW_DOT_HPP

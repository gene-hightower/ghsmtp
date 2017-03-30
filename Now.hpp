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
  {
    auto tz = date::current_zone();
    auto zoned = date::make_zoned(tz, date::floor<std::chrono::seconds>(v_));
    // RFC 5322 date-time section 3.3.
    str_ = date::format("%a, %d %b %Y %H:%M:%S %z", zoned);
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

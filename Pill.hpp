#ifndef PILL_DOT_HPP
#define PILL_DOT_HPP

#include <climits>
#include <cstddef>
#include <ostream>

// A pill is a unit of entropy.

class Pill {
public:
  Pill();
  bool operator==(Pill const& that) const { return this->s_ == that.s_; }
  bool operator!=(Pill const& that) const { return !(*this == that); }

private:
  unsigned long long s_;

  static constexpr size_t b32_ndigits_ = ((sizeof(s_) * CHAR_BIT) + 4) / 5;
  char b32_str_[b32_ndigits_ + 1];

  friend std::ostream& operator<<(std::ostream& s, Pill const& p)
  {
    return s << p.b32_str_;
  }
};

#endif // PILL_DOT_HPP

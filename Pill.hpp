#ifndef PILL_DOT_HPP
#define PILL_DOT_HPP

#include <climits>
#include <cstddef>
#include <cstring>
#include <ostream>
#include <string_view>

#include "pcg.hpp"

// A pill is a unit of entropy.

class Pill {
public:
  Pill();

  bool operator==(Pill const& that) const { return this->s_ == that.s_; }
  bool operator!=(Pill const& that) const { return !(*this == that); }

  std::string_view as_string_view() const
  {
    return std::string_view{b32_str_, b32_ndigits_};
  }

private:
  unsigned long long s_;

  auto static constexpr b32_ndigits_ = ((sizeof(s_) * CHAR_BIT) + 4) / 5;
  char b32_str_[b32_ndigits_ + 1];

  friend std::ostream& operator<<(std::ostream& s, Pill const& p)
  {
    return s << p.as_string_view();
  }

  inline static pcg_extras::seed_seq_from<std::random_device> seed_source_;
  inline static pcg64 rng_{seed_source_};
};

#endif // PILL_DOT_HPP

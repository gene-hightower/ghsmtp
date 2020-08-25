#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include "IP.hpp"

#include <iostream>
#include <string>
#include <string_view>

#include "iequal.hpp"

class Domain {
public:
  Domain() = default;

  explicit Domain(std::string_view dom) { set(dom); }

  Domain& operator=(std::string_view dom)
  {
    set(dom);
    return *this;
  }

  void set(std::string_view dom);

  inline void clear();

  bool empty() const { return ascii_.empty(); }

  inline static std::string_view remove_trailing_dot(std::string_view a);
  inline static bool             match(std::string_view a, std::string_view b);

  bool operator==(std::string_view rhs) const { return match(ascii_, rhs); }
  bool operator!=(std::string_view rhs) const { return !(*this == rhs); }

  bool operator==(Domain const& rhs) const { return match(ascii_, rhs.ascii_); }
  bool operator!=(Domain const& rhs) const { return !(*this == rhs); }

  bool is_address_literal() const { return is_address_literal_; }
  bool is_unicode() const { return utf8() != ascii(); }

  std::string const& ascii() const { return ascii_; }
  std::string const& utf8() const { return utf8_; }

private:
  std::string ascii_;
  std::string utf8_;
  bool        is_address_literal_{false};
};

inline void Domain::clear()
{
  ascii_.clear();
  utf8_.clear();
  is_address_literal_ = false;
}

inline std::string_view Domain::remove_trailing_dot(std::string_view a)
{
  if (a.length() && (a.back() == '.')) {
    a.remove_suffix(1);
  }
  return a;
}

inline bool Domain::match(std::string_view a, std::string_view b)
{
  return iequal(remove_trailing_dot(a), remove_trailing_dot(b));
}

inline std::ostream& operator<<(std::ostream& os, Domain const& dom)
{
  if (dom.is_unicode())
    return os << '{' << dom.ascii() << ',' << dom.utf8() << '}';
  return os << dom.ascii();
}

namespace std {
template <>
struct hash<Domain> {
  std::size_t operator()(Domain const& k) const
  {
    return hash<std::string>()(k.ascii());
  }
};
} // namespace std

#endif // DOMAIN_DOT_HPP

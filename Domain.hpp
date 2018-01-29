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
  Domain(std::string_view dom) { set(dom); }
  Domain& operator=(std::string_view s)
  {
    set(s);
    return *this;
  }

  void set(std::string_view dom);

  inline void clear();
  bool empty() const { return lc_.empty(); }

  inline static bool match(std::string_view a, std::string_view b);

  bool operator==(std::string_view rhs) const { return match(lc_, rhs); }
  bool operator!=(std::string_view rhs) const { return !(*this == rhs); }

  bool operator==(Domain const& rhs) const { return match(lc_, rhs.lc_); }
  bool operator!=(Domain const& rhs) const { return !(*this == rhs); }

  bool is_address_literal() const { return is_address_literal_; }
  bool is_unicode() const { return utf8() != ascii(); }

  std::string const& lc() const { return lc_; }
  std::string const& ascii() const { return ascii_; }
  std::string const& utf8() const { return utf8_; }

  inline std::string address() const;

private:
  std::string lc_;
  std::string ascii_;
  std::string utf8_;

  bool is_address_literal_{false};
};

inline void Domain::clear()
{
  lc_.clear();
  ascii_.clear();
  utf8_.clear();
  is_address_literal_ = false;
}

inline bool Domain::match(std::string_view a, std::string_view b)
{
  if ((0 != a.length()) && ('.' == a.back())) {
    a.remove_suffix(1);
  }
  if ((0 != b.length()) && ('.' == b.back())) {
    b.remove_suffix(1);
  }
  return iequal(a, b);
}

inline std::string Domain::address() const
{
  if (is_address_literal())
    return std::string(IP::as_address(ascii_));
  throw std::runtime_error("domain is not an address");
}

inline std::ostream& operator<<(std::ostream& os, Domain const& dom)
{
  if (dom.is_unicode())
    return os << '{' << dom.ascii() << ',' << dom.utf8() << '}';
  return os << dom.ascii();
}

#endif // DOMAIN_DOT_HPP

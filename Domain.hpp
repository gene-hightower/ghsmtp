#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include <boost/algorithm/string/predicate.hpp>

#include <experimental/string_view>

class Domain {
public:
  Domain() = default;

  Domain(std::experimental::string_view dom) { set(dom); }

  void set(std::experimental::string_view dom);
  void clear();
  bool empty() const { return ascii_.empty() && utf8_.empty(); }

  static bool match(std::experimental::string_view a,
                    std::experimental::string_view b)
  {
    if ((0 != a.length()) && ('.' == a.back())) {
      a.remove_suffix(1);
    }
    if ((0 != b.length()) && ('.' == b.back())) {
      b.remove_suffix(1);
    }
    return boost::iequals(a, b);
  }

  bool operator==(std::string const& rhs) const
  {
    return match(ascii_, rhs.c_str());
  }
  bool operator!=(std::string const& rhs) const { return !(*this == rhs); }

  bool operator==(char const* rhs) const { return match(ascii_, rhs); }
  bool operator!=(char const* rhs) const { return !(*this == rhs); }

  bool operator==(Domain const& rhs) const { return match(ascii_, rhs.ascii_); }
  bool operator!=(Domain const& rhs) const { return !(*this == rhs); }

  Domain& operator=(char const* p)
  {
    set(p);
    return *this;
  }
  Domain& operator=(std::string const& s)
  {
    set(s.c_str());
    return *this;
  }

  bool is_address_literal() const { return is_address_literal_; }

  std::string const& ascii() const { return ascii_; }
  std::string const& utf8() const { return utf8_; }

private:
  std::string ascii_;
  std::string utf8_;

  bool is_address_literal_{false};

  friend std::ostream& operator<<(std::ostream& os, Domain const& dom)
  {
    if (dom.ascii() == dom.utf8()) {
      return os << dom.ascii();
    }
    return os << '{' << dom.ascii() << ',' << dom.utf8() << '}';
  }
};

#endif // DOMAIN_DOT_HPP

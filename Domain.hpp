#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include <boost/algorithm/string/predicate.hpp>
#include <experimental/string_view>

class Domain {
public:
  Domain() = default;
  Domain(char const* dom);
  ~Domain();

  void set(char const* dom);

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

  bool operator==(Domain const& rhs) const { return match(ascii_, rhs.ascii_); }

  char const* ascii() const { return ascii_; }
  char const* utf8() const { return utf8_; }

private:
  char* ascii_{nullptr};
  char* utf8_{nullptr};

  friend std::ostream& operator<<(std::ostream& os, Domain const& dom)
  {
    return os << "{\"" << dom.ascii() << "\", \"" << dom.utf8() << "\"}";
  }
};

#endif // DOMAIN_DOT_HPP

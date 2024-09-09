#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include "IP.hpp"

#include <compare>
#include <iostream>
#include <string>
#include <string_view>

#include "iequal.hpp"

// The 'domain' part of an email address: DNS domain, or IP address, or address
// literal, or empty.

class Domain {
public:
  Domain() = default;

  inline explicit Domain(std::string_view dom);

  inline static bool
  validate(std::string_view domain, std::string& msg, Domain& dom);

  inline void clear();

  inline bool empty() const;

  inline bool operator==(Domain const& rhs) const;
  inline auto operator<=>(Domain const& rhs) const;

  inline bool is_address_literal() const;
  inline bool is_unicode() const;

  inline std::string const& ascii() const;
  inline std::string const& utf8() const;

private:
  bool set_(std::string_view dom, bool should_throw, std::string& msg);

  std::string ascii_; // A-labels
  std::string utf8_;  // U-labels, or empty

  bool is_address_literal_{false};
};

Domain::Domain(std::string_view dom)
{
  std::string msg;
  set_(dom, true /* throw */, msg);
}

bool Domain::validate(std::string_view domain, std::string& msg, Domain& dom)
{
  return dom.set_(domain, false /* don't throw */, msg);
}

void Domain::clear()
{
  ascii_.clear();
  utf8_.clear();
  is_address_literal_ = false;
}

bool Domain::empty() const { return ascii_.empty(); }

bool Domain::operator==(Domain const& rhs) const
{
  return ascii_ == rhs.ascii_;
}

auto Domain::operator<=>(const Domain& rhs) const
{
  return ascii_ <=> rhs.ascii_;
}

bool Domain::is_address_literal() const { return is_address_literal_; }
bool Domain::is_unicode() const
{
  return (!utf8().empty()) && (utf8() != ascii());
}

std::string const& Domain::ascii() const { return ascii_; }
std::string const& Domain::utf8() const
{
  return utf8_.empty() ? ascii_ : utf8_;
}

inline std::ostream& operator<<(std::ostream& os, Domain const& dom)
{
  if (dom.is_unicode())
    return os << '{' << dom.ascii() << ',' << dom.utf8() << '}';
  return os << dom.ascii();
}

namespace domain {
bool is_fully_qualified(Domain const& dom, std::string& msg);
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

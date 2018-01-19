#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include "IP.hpp"

#include <iostream>
#include <string>
#include <string_view>

#include <glog/logging.h>

#include "iequal.hpp"

class Domain {
public:
  Domain() = default;
  inline Domain(std::string_view dom);

  inline auto operator=(std::string_view s) -> Domain&;

  auto set(std::string_view dom) -> void;

  inline auto clear() -> void;
  inline auto empty() const -> bool;

  constexpr static auto match(std::string_view a, std::string_view b) -> bool;

  inline auto operator==(std::string_view rhs) const -> bool;
  inline auto operator!=(std::string_view rhs) const -> bool;

  inline auto operator==(Domain const& rhs) const -> bool;
  inline auto operator!=(Domain const& rhs) const -> bool;

  inline auto is_address_literal() const -> bool;
  inline auto is_unicode() const -> bool;

  inline auto ascii() const -> std::string const&;
  inline auto utf8() const -> std::string const&;

  inline auto address() const -> std::string;

private:
  std::string ascii_;
  std::string utf8_;

  bool is_address_literal_{false};
};

inline Domain::Domain(std::string_view dom) { set(dom); }

inline auto Domain::operator=(std::string_view s) -> Domain&
{
  set(s);
  return *this;
}

inline auto Domain::clear() -> void
{
  ascii_.clear();
  utf8_.clear();
  is_address_literal_ = false;
}

inline auto Domain::empty() const -> bool
{
  return ascii_.empty() && utf8_.empty();
}

constexpr auto Domain::match(std::string_view a, std::string_view b) -> bool
{
  if ((0 != a.length()) && ('.' == a.back())) {
    a.remove_suffix(1);
  }
  if ((0 != b.length()) && ('.' == b.back())) {
    b.remove_suffix(1);
  }
  return iequal(a, b);
}

inline auto Domain::operator==(std::string_view rhs) const -> bool
{
  return match(ascii_, rhs);
}

inline auto Domain::operator!=(std::string_view rhs) const -> bool
{
  return !(*this == rhs);
}

inline auto Domain::operator==(Domain const& rhs) const -> bool
{
  return match(ascii_, rhs.ascii_);
}

inline auto Domain::operator!=(Domain const& rhs) const -> bool
{
  return !(*this == rhs);
}

inline auto Domain::is_address_literal() const -> bool
{
  return is_address_literal_;
}

inline auto Domain::is_unicode() const -> bool { return utf8() != ascii(); }

inline auto Domain::ascii() const -> std::string const& { return ascii_; }

inline auto Domain::utf8() const -> std::string const& { return utf8_; }

inline auto Domain::address() const -> std::string
{
  if (is_address_literal())
    return std::string(IP::as_address(ascii_));
  LOG(FATAL) << "domain name is not an address";
}

inline auto operator<<(std::ostream& os, Domain const& dom) -> std::ostream&
{
  if (dom.is_unicode())
    return os << '{' << dom.ascii() << ',' << dom.utf8() << '}';
  return os << dom.ascii();
}

#endif // DOMAIN_DOT_HPP

#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include "Domain.hpp"

#include <ostream>
#include <string>
#include <utility>

#include <boost/algorithm/string.hpp>

class Mailbox {
public:
  Mailbox() = default;
  Mailbox(std::string local_part, std::string domain);

  auto inline set_local(std::string local_part) -> void;
  auto inline set_domain(std::string domain) -> void;
  auto inline clear() -> void;
  auto inline local_part() const -> std::string const&;
  auto inline domain() const -> Domain const&;
  auto inline empty() const -> bool;
  operator std::string() const;

private:
  std::string local_part_;
  Domain domain_;
};

inline Mailbox::Mailbox(std::string local_part, std::string domain)
{
  set_local(local_part);
  set_domain(domain);
}

auto inline Mailbox::set_local(std::string local_part) -> void
{
  local_part_ = std::move(local_part);
}

auto inline Mailbox::set_domain(std::string domain) -> void
{
  boost::to_lower(domain);
  domain_.set(domain);
}

auto inline Mailbox::clear() -> void
{
  local_part_.clear();
  domain_.clear();
}

auto inline Mailbox::local_part() const -> std::string const&
{
  return local_part_;
}
auto inline Mailbox::domain() const -> Domain const& { return domain_; }

auto inline Mailbox::empty() const -> bool
{
  return local_part().empty() && domain().empty();
}

inline Mailbox::operator std::string() const
{
  return local_part() + (domain().empty() ? "" : ("@" + domain().utf8()));
}

auto inline operator<<(std::ostream& s, Mailbox const& mb) -> std::ostream&
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

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
  Mailbox(std::string local_part, std::string domain)
    : local_part_{std::move(local_part)}
    , domain_str_{std::move(domain)}
  {
    boost::to_lower(domain_str_);
    domain_.set(domain_str_.c_str());
  }
  void clear()
  {
    local_part_.clear();
    domain_str_.clear();
    domain_.clear();
  }
  std::string const& local_part() const { return local_part_; }
  Domain const& domain() const { return domain_; }

  bool empty() const { return local_part().empty() && domain().empty(); }

  auto length() const
  {
    return local_part().length()
           + (domain().utf8().length() ? (domain().utf8().length() + 1) : 0);
  }

  operator std::string() const
  {
    return local_part() + (domain().empty() ? "" : ("@" + domain().utf8()));
  }

  bool operator==(Mailbox const& rhs) const
  {
    return (local_part() == rhs.local_part()) && (domain() == rhs.domain());
  }

private:
  std::string local_part_;
  std::string domain_str_;
  Domain domain_;
};

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

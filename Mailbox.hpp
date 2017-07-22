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
  {
    set_local(local_part);
    set_domain(domain);
  }
  void set_local(std::string local_part)
  {
    local_part_ = std::move(local_part);
  }
  void set_domain(std::string domain)
  {
    boost::to_lower(domain);
    domain_.set(domain.c_str());
  }
  void clear()
  {
    local_part_.clear();
    domain_.clear();
  }
  std::string const& local_part() const { return local_part_; }
  Domain const& domain() const { return domain_; }

  bool empty() const { return local_part().empty() && domain().empty(); }

  operator std::string() const
  {
    return local_part() + (domain().empty() ? "" : ("@" + domain().utf8()));
  }

private:
  std::string local_part_;
  Domain domain_;
};

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

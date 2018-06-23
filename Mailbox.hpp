#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include "Domain.hpp"

#include <ostream>
#include <string>
#include <utility>

class Mailbox {
public:
  Mailbox() = default;
  Mailbox(std::string_view local_part, std::string_view domain)
  {
    set_local(local_part);
    set_domain(domain);
  }

  void set_local(std::string_view local_part) { local_part_ = local_part; }
  void set_domain(std::string_view d) { domain_.set(d); }
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
    std::string s;
    s.reserve(local_part_.length() + domain().utf8().length() + 1);
    s = local_part();
    if (!domain().empty()) {
      s += "@" + domain().utf8();
    }
    return s;
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

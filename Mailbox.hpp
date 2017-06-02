#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include <ostream>
#include <string>
#include <utility>

#include <boost/algorithm/string.hpp>

class Mailbox {
public:
  Mailbox() = default;
  Mailbox(std::string local_part, std::string domain)
    : local_part_{std::move(local_part)}
    , domain_{std::move(domain)}
  {
    boost::to_lower(domain_);
  }
  void clear()
  {
    local_part_.clear();
    domain_.clear();
  }
  std::string const& local_part() const { return local_part_; }
  std::string const& domain() const { return domain_; }

  bool empty() const { return local_part_.empty() && domain_.empty(); }

  operator std::string() const
  {
    return local_part() + (domain().empty() ? "" : ("@" + domain()));
  }

  bool operator==(Mailbox const& rhs) const
  {
    return ((local_part_ == rhs.local_part_) && (domain_ == rhs.domain_));
  }

private:
  std::string local_part_;
  std::string domain_;
};

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

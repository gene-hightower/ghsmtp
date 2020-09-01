#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include "Domain.hpp"

#include <ostream>
#include <string>
#include <utility>

class Mailbox {
public:
  Mailbox() = default;
  Mailbox(std::string_view mailbox);
  Mailbox(std::string_view local_part, std::string_view domain)
  {
    set_local(local_part);
    set_domain(domain);
  }
  Mailbox(std::string_view local_part, Domain domain)
  {
    set_local(local_part);
    set_domain(domain);
  }

  void set_local(std::string_view local_part) { local_part_ = local_part; }
  void set_domain(std::string_view d) { domain_.set(d); }
  void set_domain(Domain d) { domain_ = d; }
  void clear()
  {
    local_part_.clear();
    domain_.clear();
  }
  std::string const& local_part() const { return local_part_; }
  Domain const&      domain() const { return domain_; }

  enum class domain_encoding : bool { ascii, utf8 };

  size_t length(domain_encoding enc = domain_encoding::utf8) const;

  bool empty() const { return length() == 0; }

  std::string as_string(domain_encoding enc = domain_encoding::utf8) const;

  operator std::string() const { return as_string(domain_encoding::utf8); }

  bool operator==(Mailbox const& rhs) const
  {
    return (local_part_ == rhs.local_part_) && (domain_ == rhs.domain_);
  }
  bool operator!=(Mailbox const& rhs) const { return !(*this == rhs); }

  static bool validate(std::string_view mailbox);

private:
  std::string local_part_;
  Domain      domain_;
};

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

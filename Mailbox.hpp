#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include "Domain.hpp"

#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

class Mailbox {
public:
  Mailbox() = default;

  // Parse the input string against the RFC-5321 Mailbox grammar, normalize any
  // Unicode, normalize Quoted-string Local-part.
  inline Mailbox(std::string_view mailbox);

  // Accept the Local-part as already validated via some external check.
  inline Mailbox(std::string_view local_part, Domain domain);

  inline static bool
  validate(std::string_view mailbox, std::string& msg, Mailbox& mbx);

  inline void set_local(std::string_view local_part);
  inline void set_domain(Domain d);
  inline void clear();

  inline std::string const& local_part() const;
  inline Domain const&      domain() const;

  enum class domain_encoding : bool { ascii, utf8 };

  size_t length(domain_encoding enc = domain_encoding::utf8) const;
  inline bool empty() const;

  std::string as_string(domain_encoding enc = domain_encoding::utf8) const;
  inline operator std::string() const;

  inline bool operator==(Mailbox const& rhs) const;
  inline bool operator!=(Mailbox const& rhs) const;

  enum class local_types : uint8_t {
    unknown,
    dot_string,
    quoted_string,
  };

  enum class domain_types : uint8_t {
    unknown,
    domain,
    address_literal,         // IP4/IP6 address literal
    general_address_literal, // some other address literal
  };

  struct parse_results {
    std::string_view local;
    std::string_view domain;
    std::string_view standardized_tag;
    local_types      local_type  = local_types::unknown;
    domain_types     domain_type = domain_types::unknown;
  };

  static std::optional<parse_results> parse(std::string_view mailbox);

private:
  bool set_(std::string_view mailbox, bool should_throw, std::string& msg);

  std::string local_part_;
  Domain      domain_;
};

Mailbox::Mailbox(std::string_view mailbox)
{
  std::string msg;
  set_(mailbox, true /* throw */, msg);
}

// Accept the inputs as already validated via some external check.
Mailbox::Mailbox(std::string_view local_part, Domain domain)
{
  set_local(local_part);
  set_domain(domain);
}

bool Mailbox::validate(std::string_view mailbox, std::string& msg, Mailbox& mbx)
{
  return mbx.set_(mailbox, false /* don't throw */, msg);
}

void Mailbox::set_local(std::string_view local_part)
{
  local_part_ = local_part;
}

void Mailbox::set_domain(Domain d) { domain_ = d; }

void Mailbox::clear()
{
  local_part_.clear();
  domain_.clear();
}

std::string const& Mailbox::local_part() const { return local_part_; }
Domain const&      Mailbox::domain() const { return domain_; }

bool Mailbox::empty() const { return length() == 0; }

Mailbox::operator std::string() const
{
  return as_string(domain_encoding::utf8);
}

bool Mailbox::operator==(Mailbox const& rhs) const
{
  return (local_part_ == rhs.local_part_) && (domain_ == rhs.domain_);
}

bool Mailbox::operator!=(Mailbox const& rhs) const { return !(*this == rhs); }

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << static_cast<std::string>(mb);
}

#endif // MAILBOX_DOT_HPP

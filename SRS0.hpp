#ifndef SRS0_DOT_HPP
#define SRS0_DOT_HPP

#include "SRS.hpp"

#include <optional>
#include <string>
#include <string_view>

#include "fs.hpp"

// sender rewriting scheme complaint

class SRS0 {
public:
  SRS0(fs::path config_path)
    : config_path_(config_path)
  {
  }

  struct from_to {
    std::string mail_from;          // from
    std::string rcpt_to_local_part; // @our-domain.com

    inline bool operator==(from_to const& rhs) const;
    inline bool empty() const;
  };

  std::string enc_reply(from_to const& reply_info) const;
  std::string enc_bounce(from_to const& bounce_info, char const* sender) const;

  std::optional<from_to> dec_reply(std::string_view addr) const;
  std::optional<from_to> dec_bounce(std::string_view addr,
                                    uint16_t         days_valid) const;

private:
  // key info, secrets
  fs::path config_path_;
  SRS      srs_;
};

inline bool SRS0::from_to::operator==(from_to const& rhs) const
{
  return (mail_from == rhs.mail_from) &&
         (rcpt_to_local_part == rhs.rcpt_to_local_part);
}

inline bool SRS0::from_to::empty() const
{
  return mail_from.empty() && rcpt_to_local_part.empty();
}

#endif // SRS0_DOT_HPP

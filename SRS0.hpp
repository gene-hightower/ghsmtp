#ifndef SRS0_DOT_HPP
#define SRS0_DOT_HPP

#include <optional>
#include <string>
#include <string_view>

#include "fs.hpp"

// sender rewriting scheme complaint

class SRS0 {
public:
  struct reply_address {
    std::string mail_from;          // from
    std::string rcpt_to_local_part; // @our-domain.com
  };

  struct bounce_address {
    std::string mail_from; // from
  };

  std::string enc_reply(reply_address const& reply_info) const;
  std::string enc_bounce(bounce_address const& bounce_info) const;

  std::optional<reply_address>  dec_reply(std::string_view addr) const;
  std::optional<bounce_address> dec_bounce(std::string_view addr,
                                           uint16_t         days_valid) const;

private:
  // key info, secrets
};

#endif // SRS0_DOT_HPP

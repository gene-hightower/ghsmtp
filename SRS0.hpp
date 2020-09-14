#ifndef SRS0_DOT_HPP
#define SRS0_DOT_HPP

#include <optional>
#include <string>
#include <string_view>

#include "fs.hpp"

// sender rewriting scheme complaint

class SRS0 {
public:
  struct from_to {
    std::string mail_from;          // from
    std::string rcpt_to_local_part; // @our-domain.com
  };

  std::string enc_reply(from_to const& reply_info) const;
  std::string enc_bounce(from_to const& bounce_info) const;

  std::optional<from_to> dec_reply(std::string_view addr) const;
  std::optional<from_to> dec_bounce(std::string_view addr,
                                    uint16_t         days_valid) const;

private:
  // key info, secrets
};

#endif // SRS0_DOT_HPP

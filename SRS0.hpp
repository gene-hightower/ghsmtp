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
  struct from_to {
    std::string mail_from;          // from
    std::string rcpt_to_local_part; // @our-domain.com

    inline bool operator==(from_to const& rhs) const;
    inline bool empty() const;
    inline void clear();
  };

  static std::string enc_reply(from_to const&   reply_info,
                               std::string_view secret);

  static std::optional<from_to> dec_reply(std::string_view addr,
                                          std::string_view secret);
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

inline void SRS0::from_to::clear()
{
  mail_from.clear();
  rcpt_to_local_part.clear();
}

#endif // SRS0_DOT_HPP

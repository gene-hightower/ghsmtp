#ifndef DNS_MESSAGE_DOT_HPP
#define DNS_MESSAGE_DOT_HPP

#include <limits>
#include <memory>

#include "DNS-rrs.hpp"

#include "iobuffer.hpp"

#include <glog/logging.h>

namespace Config {
auto constexpr max_udp_sz{uint16_t(4 * 1024)};
} // namespace Config

namespace DNS {

class message {
public:
  using octet       = unsigned char;
  using container_t = iobuffer<octet>;

  message() = default;

  explicit message(container_t::size_type sz)
    : buf_(sz)
  {
    CHECK_LE(sz, std::numeric_limits<uint16_t>::max());
  }

  explicit message(container_t&& buf)
    : buf_{buf}
  {
    CHECK_LE(buf.size(), std::numeric_limits<uint16_t>::max());
  }

  operator std::span<octet>() { return {buf_.data(), buf_.size()}; }
  operator std::span<octet const>() const { return {buf_.data(), buf_.size()}; }

  uint16_t id() const;

  static size_t min_sz();

private:
  container_t buf_;
};

DNS::message
create_question(char const* name, DNS::RR_type type, uint16_t cls, uint16_t id);

void check_answer(bool&          nx_domain,
                  bool&          bogus_or_indeterminate,
                  uint16_t&      rcode,
                  uint16_t&      extended_rcode,
                  bool&          truncation,
                  bool&          authentic_data,
                  bool&          has_record,
                  message const& question,
                  message const& answer,
                  RR_type        type,
                  char const*    name);

RR_collection get_records(message const& pkt, bool& bogus_or_indeterminate);

} // namespace DNS

#endif // DNS_MESSAGE_DOT_HPP

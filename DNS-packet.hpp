#ifndef DNS_PACKET_DOT_HPP
#define DNS_PACKET_DOT_HPP

#include <memory>

#include "DNS-rrs.hpp"

#include "iobuffer.hpp"

#include <glog/logging.h>

namespace Config {
auto constexpr max_udp_sz{uint16_t(4 * 1024)};
} // namespace Config

namespace DNS {

class packet {
public:
  using octet = unsigned char;

  using container_t = iobuffer<octet>;

  packet() {}

  explicit packet(container_t::size_type sz)
    : bfr_(sz)
  {
    CHECK_LE(sz, std::numeric_limits<uint16_t>::max());
  }

  explicit packet(container_t&& bfr)
    : bfr_{std::move(bfr)}
  {
    CHECK_LE(size(), std::numeric_limits<uint16_t>::max());
  }

  uint16_t size() const { return bfr_.size(); }

  auto begin() const { return bfr_.data(); }
  auto end() const { return bfr_.data() + bfr_.size(); }

  uint16_t id() const;

private:
  container_t bfr_;
};

inline auto begin(packet const& pkt) { return pkt.begin(); }
inline auto end(packet const& pkt) { return pkt.end(); }
inline auto size(packet const& pkt) { return pkt.size(); }

size_t min_udp_sz();

DNS::packet
create_question(char const* name, DNS::RR_type type, uint16_t cls, uint16_t id);

void check_answer(bool&         nx_domain,
                  bool&         bogus_or_indeterminate,
                  uint16_t&     rcode,
                  uint16_t&     extended_rcode,
                  bool&         authentic_data,
                  bool&         has_record,
                  packet const& question,
                  packet const& answer,
                  RR_type       type,
                  char const*   name);

RR_collection get_records(packet const& pkt, bool& bogus_or_indeterminate);

} // namespace DNS

#endif // DNS_PACKET_DOT_HPP

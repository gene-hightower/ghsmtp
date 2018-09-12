#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

#include <memory>

#include "DNS-rrs.hpp"
#include "Sock.hpp"
#include "default_init_allocator.hpp"

#include <glog/logging.h>

namespace DNS {

class packet {
public:
  using octet = unsigned char;

  using container_t
      = std::vector<octet, default_init_allocator<octet>>;

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

private:
  container_t bfr_;
};

inline auto begin(packet const& pkt) { return pkt.begin(); }
inline auto end(packet const& pkt) { return pkt.end(); }
inline auto size(packet const& pkt) { return pkt.size(); }

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver();

  RR_collection get_records(RR_type typ, char const* name);
  RR_collection get_records(RR_type typ, std::string const& name)
  {
    return get_records(typ, name.c_str());
  }

  std::vector<std::string> get_strings(RR_type typ, char const* name);
  std::vector<std::string> get_strings(RR_type typ, std::string const& name)
  {
    return get_strings(typ, name.c_str());
  }

  packet xchg(packet const& q);

private:
  std::unique_ptr<Sock> ns_sock_;
  int ns_;
  int ns_fd_;
};

class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver& res, RR_type type, char const* name);
  Query(Resolver& res, RR_type type, std::string const& name)
    : Query(res, type, name.c_str())
  {
  }

  bool authentic_data() const { return authentic_data_; }
  bool bogus_or_indeterminate() const { return bogus_or_indeterminate_; }
  bool nx_domain() const { return nx_domain_; }

  bool has_record() const { return has_record_; }
  RR_collection get_records();
  std::vector<std::string> get_strings();

  uint16_t rcode() const { return rcode_; }
  uint16_t extended_rcode() const { return extended_rcode_; }

private:
  bool xchg_(Resolver& res, uint16_t id);
  void check_answer_(Resolver& res, RR_type type, char const* name);

  uint16_t rcode_{0};
  uint16_t extended_rcode_{0};

  RR_type type_;

  packet q_;
  packet a_;

  bool authentic_data_{false};
  bool bogus_or_indeterminate_{false};
  bool nx_domain_{false};
  bool has_record_{false};
};

inline std::vector<std::string>
get_strings(Resolver& res, RR_type type, char const* name)
{
  return res.get_strings(type, name);
}

inline std::vector<std::string>
get_strings(Resolver& res, RR_type type, std::string const& name)
{
  return res.get_strings(type, name.c_str());
}

inline bool has_record(Resolver& res, RR_type type, char const* name)
{
  Query q(res, type, name);
  return q.has_record();
}

inline bool has_record(Resolver& res, RR_type type, std::string const& name)
{
  return has_record(res, type, name.c_str());
}
} // namespace DNS

#endif // DNS_DOT_HPP

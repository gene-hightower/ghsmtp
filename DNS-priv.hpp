#ifndef DNS_PRIV_DOT_HPP
#define DNS_PRIV_DOT_HPP

#include <memory>

#include "DNS-rrs.hpp"
#include "Sock.hpp"

namespace DNS {

struct pkt {
  std::unique_ptr<unsigned char[]> bfr;
  uint16_t sz;
};

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver();

  RR_set get_records(RR_type typ, char const* name);
  RR_set get_records(RR_type typ, std::string const& name)
  {
    return get_records(typ, name.c_str());
  }

  std::vector<std::string> get_strings(RR_type typ, char const* name);
  std::vector<std::string> get_strings(RR_type typ, std::string const& name)
  {
    return get_strings(typ, name.c_str());
  }

  pkt xchg(pkt const& q);

private:
  std::unique_ptr<Sock> ns_sock_;
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
  RR_set get_records();
  std::vector<std::string> get_strings();

  uint16_t rcode() const { return rcode_; }
  uint16_t extended_rcode() const { return extended_rcode_; }

private:
  uint16_t rcode_{0};
  uint16_t extended_rcode_{0};

  RR_type type_;

  pkt q_;
  pkt a_;

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

#endif // DNS_PRIV_DOT_HPP

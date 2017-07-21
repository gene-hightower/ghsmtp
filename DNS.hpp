#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

#include <ldns/packet.h>
#include <ldns/rr.h>

typedef struct ldns_struct_resolver ldns_resolver;

#include <iostream>
#include <string>
#include <vector>

namespace DNS {

enum class RR_type {
  A = LDNS_RR_TYPE_A,
  AAAA = LDNS_RR_TYPE_AAAA,
  CNAME = LDNS_RR_TYPE_CNAME,
  MX = LDNS_RR_TYPE_MX,
  PTR = LDNS_RR_TYPE_PTR,
  TLSA = LDNS_RR_TYPE_TLSA,
  TXT = LDNS_RR_TYPE_TXT,
};

enum class Pkt_rcode {
  NOERROR = LDNS_RCODE_NOERROR,
  FORMERR = LDNS_RCODE_FORMERR,
  SERVFAIL = LDNS_RCODE_SERVFAIL,
  NXDOMAIN = LDNS_RCODE_NXDOMAIN,
  NOTIMPL = LDNS_RCODE_NOTIMPL,
  REFUSED = LDNS_RCODE_REFUSED,
  YXDOMAIN = LDNS_RCODE_YXDOMAIN,
  YXRRSET = LDNS_RCODE_YXRRSET,
  NXRRSET = LDNS_RCODE_NXRRSET,
  NOTAUTH = LDNS_RCODE_NOTAUTH,
  NOTZONE = LDNS_RCODE_NOTZONE,
  INTERNAL = 666,
};

char const* as_cstr(Pkt_rcode pkt_rcode);
std::ostream& operator<<(std::ostream& os, Pkt_rcode pkt_rcode);

template <RR_type type>
class Query;
template <RR_type type>
class Rrlist;

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver();
  ~Resolver();

private:
  ldns_resolver* res_;

  friend class Query<RR_type::A>;
  friend class Query<RR_type::AAAA>;
  friend class Query<RR_type::MX>;
  friend class Query<RR_type::PTR>;
  friend class Query<RR_type::TXT>;
};

class Domain {
public:
  Domain(Domain const&) = delete;
  Domain& operator=(Domain const&) = delete;

  explicit Domain(std::string domain);
  ~Domain();

private:
  std::string domain_;
  ldns_rdf* drdfp_;

  friend class Query<RR_type::A>;
  friend class Query<RR_type::AAAA>;
  friend class Query<RR_type::MX>;
  friend class Query<RR_type::PTR>;
  friend class Query<RR_type::TXT>;
};

template <RR_type type>
class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, Domain const& dom);
  ~Query();

  Pkt_rcode get_rcode() const;

private:
  ldns_pkt* p_{nullptr};

  friend class Rrlist<type>;
};

template <RR_type type>
class Rrlist {
public:
  Rrlist(Rrlist const&) = delete;
  Rrlist& operator=(Rrlist const&) = delete;

  explicit Rrlist(Query<type> const& q);
  ~Rrlist();
  bool empty() const;

  std::vector<std::string> get() const;

private:
  ldns_rr_list* rrlst_{nullptr};

  std::string rr_name_str(ldns_rdf const* rdf) const;
  std::string rr_str(ldns_rdf const* rdf) const;
};

template <RR_type type>
bool has_record(Resolver const& res, std::string addr);

template <RR_type type>
std::vector<std::string> get_records(Resolver const& res, std::string addr);

} // namespace DNS

#endif // DNS_DOT_HPP

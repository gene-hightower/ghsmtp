#ifndef DNS_LDNS_DOT_HPP
#define DNS_LDNS_DOT_HPP

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

#include <netinet/in.h>

// forward decl
typedef struct ldns_struct_pkt ldns_pkt;
typedef struct ldns_struct_rdf ldns_rdf;
typedef struct ldns_struct_resolver ldns_resolver;
typedef struct ldns_struct_rr_list ldns_rr_list;

namespace DNS {

enum class RRtype : uint16_t {
  // RFC 1035 section 3.2.2 TYPE values:
  NONE,
  A,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  RR_NULL,
  WKS,
  PTR,
  HINFO,
  MINFO,
  MX,
  TXT,

  // RFC 3596 section 2.1 AAAA record type
  AAAA = 28,

  // RFC 6698 section 7.1 TLSA RRtype
  TLSA = 52,
};

auto constexpr RRtype_c_str(RRtype const& type)
{
  // clang-format off
  switch (type) {
  case RRtype::NONE:   return "NONE";
  case RRtype::A:      return "A";
  case RRtype::NS:     return "NS";
  case RRtype::MD:     return "MD";
  case RRtype::MF:     return "MF";
  case RRtype::CNAME:  return "CNAME";
  case RRtype::SOA:    return "SOA";
  case RRtype::MB:     return "MB";
  case RRtype::MG:     return "MG";
  case RRtype::MR:     return "MR";
  case RRtype::RR_NULL:return "RR_NULL";
  case RRtype::WKS:    return "WKS";
  case RRtype::PTR:    return "PTR";
  case RRtype::HINFO:  return "HINFO";
  case RRtype::MINFO:  return "MINFO";
  case RRtype::MX:     return "MX";
  case RRtype::TXT:    return "TXT";
  case RRtype::AAAA:   return "AAAA";
  case RRtype::TLSA:   return "TLSA";
  }
  return "** Unknown **";
  // clang-format on
}

class RR_A {
public:
  RR_A(uint8_t const* rd, size_t sz);

  sockaddr_in const& addr() const { return addr_; }
  char const* c_str() const { return str_; }

private:
  sockaddr_in addr_;
  char str_[INET_ADDRSTRLEN];
};

class RR_CNAME {
public:
  explicit RR_CNAME(std::string cname)
    : cname_(cname)
  {
  }

  std::string const& str() const { return cname_; }

private:
  std::string cname_;
};

// RFC 2181 section 10.2 PTR records
class RR_PTR {
public:
  explicit RR_PTR(std::string ptrdname)
    : ptrdname_(ptrdname)
  {
  }

  std::string const& str() const { return ptrdname_; }

private:
  std::string ptrdname_;
};

class RR_MX {
public:
  RR_MX(std::string exchange, uint16_t preference)
    : exchange_(exchange)
    , preference_(preference)
  {
  }

  std::string const& exchange() const { return exchange_; }
  uint16_t preference() const { return preference_; }

private:
  std::string exchange_;
  uint16_t preference_;
};

class RR_TXT {
public:
  explicit RR_TXT(std::string txt_data)
    : txt_data_(txt_data)
  {
  }

  std::string const& str() const { return txt_data_; }

private:
  std::string txt_data_;
};

class RR_AAAA {
public:
  RR_AAAA(uint8_t const* rd, size_t sz);

  sockaddr_in6 const& addr() const { return addr_; }
  char const* c_str() const { return str_; }

private:
  sockaddr_in6 addr_;
  char str_[INET6_ADDRSTRLEN];
};

using RR = std::variant<RR_A, RR_CNAME, RR_PTR, RR_MX, RR_TXT, RR_AAAA>;

using RR_set = std::vector<RR>;

class Domain {
public:
  Domain(Domain const&) = delete;
  Domain& operator=(Domain const&) = delete;

  explicit Domain(char const* domain);
  ~Domain();

  std::string const& str() const { return str_; }
  ldns_rdf* get() const { return rdfp_; }

private:
  std::string str_;
  ldns_rdf* rdfp_;
};

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver();
  ~Resolver();

  RR_set get_records(RRtype typ, Domain const& domain);
  ldns_resolver* get() const { return res_; }

private:
  ldns_resolver* res_;
};

class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, RRtype type, Domain const& dom);
  ~Query();

  // Pkt_rcode get_rcode() const;

  bool bogus_or_indeterminate() const { return bogus_or_indeterminate_; }
  bool nx_domain() const { return nx_domain_; }
  ldns_pkt* get() const { return p_; }

private:
  ldns_pkt* p_{nullptr};

  bool bogus_or_indeterminate_{false};
  bool nx_domain_{false};
};

class RR_list {
public:
  RR_list(RR_list const&) = delete;
  RR_list& operator=(RR_list const&) = delete;

  explicit RR_list(Query const& q);
  ~RR_list();

  RR_set get() const;

private:
  ldns_rr_list* rrlst_answer_{nullptr};
  // ldns_rr_list* rrlst_additional_{nullptr};
};

} // namespace DNS

#endif // DNS_LDNS_DOT_HPP

#ifndef DNS_LDNS_DOT_HPP
#define DNS_LDNS_DOT_HPP

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

#include <netinet/in.h>

#include "DNS-rrs.hpp"

// forward decl
typedef struct ldns_struct_pkt      ldns_pkt;
typedef struct ldns_struct_rdf      ldns_rdf;
typedef struct ldns_struct_resolver ldns_resolver;
typedef struct ldns_struct_rr_list  ldns_rr_list;

namespace DNS_ldns {

class Domain {
public:
  Domain(Domain const&) = delete;
  Domain& operator=(Domain const&) = delete;

  explicit Domain(char const* domain);
  explicit Domain(std::string const& domain);
  ~Domain();

  std::string const& str() const { return str_; }
  ldns_rdf*          get() const { return rdfp_; }

private:
  std::string str_;
  ldns_rdf*   rdfp_;

  friend std::ostream& operator<<(std::ostream& os, Domain const& dom)
  {
    return os << dom.str();
  }
};

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver();
  ~Resolver();

  DNS::RR_collection get_records(DNS::RR_type       typ,
                                 std::string const& domain) const
  {
    return get_records(typ, domain.c_str());
  }
  DNS::RR_collection get_records(DNS::RR_type typ, char const* domain) const;

  std::vector<std::string> get_strings(DNS::RR_type       typ,
                                       std::string const& domain) const
  {
    return get_strings(typ, domain.c_str());
  }
  std::vector<std::string> get_strings(DNS::RR_type typ,
                                       char const*  domain) const;

  ldns_resolver* get() const { return res_; }

private:
  ldns_resolver* res_;
};

class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, DNS::RR_type type, std::string const& dom);
  Query(Resolver const& res, DNS::RR_type type, char const* dom);
  ~Query();

  ldns_pkt* get() const { return p_; }

  bool authentic_data() const { return authentic_data_; }
  bool bogus_or_indeterminate() const { return bogus_or_indeterminate_; }
  bool nx_domain() const { return nx_domain_; }

  DNS::RR_collection       get_records() const;
  std::vector<std::string> get_strings() const;

private:
  ldns_pkt* p_{nullptr};

  bool authentic_data_{false};
  bool bogus_or_indeterminate_{false};
  bool nx_domain_{false};
};

class RR_list {
public:
  RR_list(RR_list const&) = delete;
  RR_list& operator=(RR_list const&) = delete;

  explicit RR_list(Query const& q);
  ~RR_list();

  DNS::RR_collection       get_records() const;
  std::vector<std::string> get_strings() const;

private:
  ldns_rr_list* rrlst_answer_{nullptr};
  ldns_rr_list* rrlst_additional_{nullptr};
};

inline std::vector<std::string>
get_strings(Resolver const& res, DNS::RR_type type, char const* domain)
{
  return res.get_strings(type, domain);
}

inline std::vector<std::string>
get_strings(Resolver const& res, DNS::RR_type type, std::string const& domain)
{
  return res.get_strings(type, domain.c_str());
}

inline bool
has_record(Resolver const& res, DNS::RR_type type, char const* domain)
{
  auto rr_set = res.get_records(type, domain);
  return !rr_set.empty();
}

inline bool
has_record(Resolver const& res, DNS::RR_type type, std::string const& domain)
{
  return has_record(res, type, domain.c_str());
}

} // namespace DNS_ldns

#endif // DNS_LDNS_DOT_HPP

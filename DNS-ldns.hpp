#ifndef DNS_LDNS_DOT_HPP
#define DNS_LDNS_DOT_HPP

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

#include <netinet/in.h>

#include "DNS-rrs.hpp"

// forward decl
typedef struct ldns_struct_pkt ldns_pkt;
typedef struct ldns_struct_rdf ldns_rdf;
typedef struct ldns_struct_resolver ldns_resolver;
typedef struct ldns_struct_rr_list ldns_rr_list;

namespace DNS {

class Domain {
public:
  Domain(Domain const&) = delete;
  Domain& operator=(Domain const&) = delete;

  explicit Domain(char const* domain);
  explicit Domain(std::string const& domain);
  ~Domain();

  std::string const& str() const { return str_; }
  ldns_rdf* get() const { return rdfp_; }

private:
  std::string str_;
  ldns_rdf* rdfp_;

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

  RR_set get_records(RR_type typ, Domain const& domain) const;
  RR_set get_records(RR_type typ, std::string const& domain) const
  {
    return get_records(typ, Domain(domain));
  }
  RR_set get_records(RR_type typ, char const* domain) const
  {
    return get_records(typ, Domain(domain));
  }

  std::vector<std::string> get_strings(RR_type typ, Domain const& domain) const;

  ldns_resolver* get() const { return res_; }

private:
  ldns_resolver* res_;
};

class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, RR_type type, Domain const& dom);
  ~Query();

  ldns_pkt* get() const { return p_; }

  bool authentic_data() const { return authentic_data_; }
  bool bogus_or_indeterminate() const { return bogus_or_indeterminate_; }
  bool nx_domain() const { return nx_domain_; }

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

  RR_set get_records() const;
  std::vector<std::string> get_strings() const;

private:
  ldns_rr_list* rrlst_answer_{nullptr};
  ldns_rr_list* rrlst_additional_{nullptr};
};

template <RR_type type>
std::vector<std::string> get_strings(Resolver const& res, Domain const& domain)
{
  return res.get_strings(type, domain);
}

template <RR_type type>
inline std::vector<std::string> get_strings(Resolver const& res,
                                            std::string const& domain)
{
  return get_strings<type>(res, Domain(domain));
}

template <RR_type type>
inline std::vector<std::string> get_strings(Resolver const& res,
                                            char const* domain)
{
  return get_strings<type>(res, Domain(domain));
}

template <RR_type type>
inline bool has_record(Resolver const& res, char const* domain)
{
  auto rr_set = res.get_records(type, Domain(domain));
  return !rr_set.empty();
}

template <RR_type type>
inline bool has_record(Resolver const& res, std::string const& domain)
{
  return has_record<type>(res, domain.c_str());
}

// Compatibility with the 1st generation:

template <RR_type type>
[[deprecated("replaced by get_strings")]] inline std::vector<std::string>
get_records(Resolver const& res, Domain const& domain)
{
  return res.get_strings(type, domain);
}

template <RR_type type>
[[deprecated("replaced by get_strings")]] inline std::vector<std::string>
get_records(Resolver const& res, std::string const& domain)
{
  return get_strings<type>(res, Domain(domain));
}

template <RR_type type>
[[deprecated("replaced by get_strings")]] inline std::vector<std::string>
get_records(Resolver const& res, char const* domain)
{
  return get_strings<type>(res, Domain(domain));
}

} // namespace DNS

std::ostream& operator<<(std::ostream& os, DNS::RR_type const& type);

#endif // DNS_LDNS_DOT_HPP

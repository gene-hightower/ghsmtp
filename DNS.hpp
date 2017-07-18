#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

#include <cstdlib>
#include <iostream>
#include <unordered_map>

#include <ldns/ldns.h>
#undef bool

#include <arpa/inet.h>

#include <glog/logging.h>

namespace DNS {

enum class RR_type {
  A = LDNS_RR_TYPE_A,
  AAAA = LDNS_RR_TYPE_AAAA,
  CNAME = LDNS_RR_TYPE_CNAME,
  PTR = LDNS_RR_TYPE_PTR,
  MX = LDNS_RR_TYPE_MX,
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

  Resolver()
  {
    CHECK(LDNS_STATUS_OK == ldns_resolver_new_frm_file(&res_, nullptr));
  }
  ~Resolver() { ldns_resolver_deep_free(res_); }

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

  explicit Domain(std::string domain)
    : domain_(domain)
    , drdfp_(CHECK_NOTNULL(ldns_dname_new_frm_str(domain_.c_str())))
  {
  }
  ~Domain() { ldns_rdf_deep_free(drdfp_); }

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

  Query(Resolver const& res, Domain const& dom)
  {
    ldns_status stat = ldns_resolver_query_status(
        &p_, res.res_, dom.drdfp_, static_cast<ldns_enum_rr_type>(type),
        LDNS_RR_CLASS_IN, LDNS_RD);

    if (stat != LDNS_STATUS_OK) {
      LOG(ERROR) << "Query (" << dom.domain_ << ") "
                 << "ldns_resolver_query_status failed: stat=="
                 << static_cast<unsigned>(stat) << " "
                 << ldns_get_errorstr_by_id(stat);
    }
  }
  ~Query()
  {
    if (p_) {
      ldns_pkt_free(p_);
    }
  }

  Pkt_rcode get_rcode() const
  {
    if (p_) {
      return static_cast<Pkt_rcode>(ldns_pkt_get_rcode(p_));
    }
    return Pkt_rcode::INTERNAL;
  }

private:
  ldns_pkt* p_{nullptr};

  friend class Rrlist<type>;
};

template <RR_type type>
class Rrlist {
public:
  Rrlist(Rrlist const&) = delete;
  Rrlist& operator=(Rrlist const&) = delete;

  explicit Rrlist(Query<type> const& q)
  {
    if (q.p_) {
      rrlst_ = ldns_pkt_rr_list_by_type(
          q.p_, static_cast<ldns_enum_rr_type>(type), LDNS_SECTION_ANSWER);
    }
  }
  ~Rrlist()
  {
    if (!empty()) // since we don't assert success in the ctr()
      ldns_rr_list_deep_free(rrlst_);
  }
  bool empty() const { return nullptr == rrlst_; }

  std::vector<std::string> get() const;

private:
  ldns_rr_list* rrlst_{nullptr};

  std::string rr_name_str(ldns_rdf const* rdf) const;
  std::string rr_str(ldns_rdf const* rdf) const;
};

template <RR_type type>
inline std::string Rrlist<type>::rr_str(ldns_rdf const* rdf) const
{
  auto data = static_cast<char const*>(rdf->_data);
  auto udata = static_cast<unsigned char const*>(rdf->_data);

  return std::string(data + 1, static_cast<size_t>(*udata));
}

template <RR_type type>
inline bool has_record(Resolver const& res, std::string addr)
{
  Domain dom(addr);
  Query<type> q(res, dom);
  Rrlist<type> rrlst(q);
  return !rrlst.empty();
}

template <RR_type type>
inline std::vector<std::string> get_records(Resolver const& res,
                                            std::string addr)
{
  Domain dom(addr);
  Query<type> q(res, dom);
  Rrlist<type> rrlst(q);
  return rrlst.get();
}

} // namespace DNS

#endif // DNS_DOT_HPP

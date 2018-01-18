#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

typedef struct ldns_struct_pkt ldns_pkt;
typedef struct ldns_struct_rdf ldns_rdf;
typedef struct ldns_struct_resolver ldns_resolver;
typedef struct ldns_struct_rr_list ldns_rr_list;

#include <iostream>
#include <string>
#include <vector>

namespace DNS {
// clang-format off

class RR_type {
public:
  RR_type(int value);           // int for ldns_rr_type

  enum class value_t {          // same values as ldns_rr_type
    NONE  = 0,
    A     = 1,
    AAAA  = 28,
    CNAME = 5,
    MX    = 15,
    PTR   = 12,
    TLSA  = 52,
    TXT   = 16,
  };

  RR_type(value_t value)
    : value_(value)
  {
  }

  static constexpr auto NONE  = value_t::NONE;
  static constexpr auto A     = value_t::A;
  static constexpr auto AAAA  = value_t::AAAA;
  static constexpr auto CNAME = value_t::CNAME;
  static constexpr auto MX    = value_t::MX;
  static constexpr auto PTR   = value_t::PTR;
  static constexpr auto TLSA  = value_t::TLSA;
  static constexpr auto TXT   = value_t::TXT;

  static constexpr char const* c_str(value_t value) {
    switch (value) {
    case NONE:  return "NONE";
    case A:     return "A";
    case AAAA:  return "AAAA";
    case CNAME: return "CNAME";
    case MX:    return "MX";
    case PTR:   return "PTR";
    case TLSA:  return "TLSA";
    case TXT:   return "TXT";
    }
    return "** unknown **";
  }

  constexpr auto c_str() const -> char const* { return c_str(value_); }
  constexpr auto value() const -> value_t { return value_; }

  constexpr explicit operator char const*() const { return c_str(); }
  constexpr operator value_t() const { return value_; }

private:
  value_t value_{NONE};
};

class Pkt_rcode {
public:
  Pkt_rcode(int value);         // int for ldns_pkt_rcode

  enum class value_t {          // same values as ldns_pkt_rcode
    NOERROR  = 0,
    FORMERR  = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMPL  = 4,
    REFUSED  = 5,
    YXDOMAIN = 6,
    YXRRSET  = 7,
    NXRRSET  = 8,
    NOTAUTH  = 9,
    NOTZONE  = 10,
    INTERNAL = 666,
  };

  Pkt_rcode(value_t value)
    : value_(value)
  {
  }

  static constexpr auto NOERROR  = value_t::NOERROR;
  static constexpr auto FORMERR  = value_t::FORMERR;
  static constexpr auto SERVFAIL = value_t::SERVFAIL;
  static constexpr auto NXDOMAIN = value_t::NXDOMAIN;
  static constexpr auto NOTIMPL  = value_t::NOTIMPL;
  static constexpr auto REFUSED  = value_t::REFUSED;
  static constexpr auto YXDOMAIN = value_t::YXDOMAIN;
  static constexpr auto YXRRSET  = value_t::YXRRSET;
  static constexpr auto NXRRSET  = value_t::NXRRSET;
  static constexpr auto NOTAUTH  = value_t::NOTAUTH;
  static constexpr auto NOTZONE  = value_t::NOTZONE;
  static constexpr auto INTERNAL = value_t::INTERNAL;

  constexpr auto value() const -> value_t { return value_; }
  constexpr operator value_t() const { return value_; }

private:
  value_t value_{NOERROR};

};
// clang-format on

} // namespace DNS

auto operator<<(std::ostream& os, DNS::RR_type::value_t const& value)
    -> std::ostream&;
auto operator<<(std::ostream& os, DNS::RR_type const& value) -> std::ostream&;

auto operator<<(std::ostream& os, DNS::Pkt_rcode::value_t const& value)
    -> std::ostream&;
auto operator<<(std::ostream& os, DNS::Pkt_rcode const& value) -> std::ostream&;

namespace DNS {

template <RR_type::value_t type>
class Query;
template <RR_type::value_t type>
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

template <RR_type::value_t type>
class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, Domain const& dom);
  ~Query();

  auto get_rcode() const -> Pkt_rcode;

private:
  ldns_pkt* p_{nullptr};

  friend class Rrlist<type>;
};

template <RR_type::value_t type>
class Rrlist {
public:
  Rrlist(Rrlist const&) = delete;
  Rrlist& operator=(Rrlist const&) = delete;

  explicit Rrlist(Query<type> const& q);
  ~Rrlist();

  auto is_empty() const -> bool;
  auto get() const -> std::vector<std::string>;

private:
  ldns_rr_list* rrlst_{nullptr};

  auto rr_name_str(ldns_rdf const* rdf) const -> std::string;
  auto rr_str(ldns_rdf const* rdf) const -> std::string;
};

template <RR_type::value_t type>
auto has_record(Resolver const& res, std::string addr) -> bool;

template <RR_type::value_t type>
auto get_records(Resolver const& res, std::string addr)
    -> std::vector<std::string>;

} // namespace DNS

#endif // DNS_DOT_HPP

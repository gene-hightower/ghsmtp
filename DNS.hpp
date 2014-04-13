/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <unordered_map>

#include <ldns/ldns.h>
#undef bool

#include <arpa/inet.h>

#include "Logging.hpp"

namespace DNS {

enum class RR_type {
  A = LDNS_RR_TYPE_A,
  CNAME = LDNS_RR_TYPE_CNAME,
  PTR = LDNS_RR_TYPE_PTR,
  MX = LDNS_RR_TYPE_MX,
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
};
}

namespace std {

template <>
struct hash<DNS::RR_type> {
  size_t operator()(DNS::RR_type const& x) const
  {
    return static_cast<size_t>(x);
  }
};

template <>
struct hash<DNS::Pkt_rcode> {
  size_t operator()(DNS::Pkt_rcode const& x) const
  {
    return static_cast<size_t>(x);
  }
};
}

namespace DNS {

extern std::unordered_map<RR_type, char const*> rr_type_to_string;
extern std::unordered_map<Pkt_rcode, char const*> pkt_rcode_to_string;

inline std::ostream& operator<<(std::ostream& s, RR_type rr_type)
{
  return s << rr_type_to_string[rr_type];
}

inline std::ostream& operator<<(std::ostream& s, Pkt_rcode pkt_rcode)
{
  return s << pkt_rcode_to_string[pkt_rcode];
}

template <RR_type T>
class Query;
template <RR_type T>
class Rrlist;

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver()
  {
    CHECK(LDNS_STATUS_OK == ldns_resolver_new_frm_file(&res_, nullptr));
  }
  ~Resolver()
  {
    ldns_resolver_deep_free(res_);
  }

private:
  ldns_resolver* res_;

  friend class Query<RR_type::A>;
  friend class Query<RR_type::PTR>;
  friend class Query<RR_type::TXT>;
};

class Domain {
public:
  Domain(Domain const&) = delete;
  Domain& operator=(Domain const&) = delete;

  explicit Domain(char const* domain)
    : domain_(CHECK_NOTNULL(ldns_dname_new_frm_str(domain)))
  {
  }
  ~Domain()
  {
    ldns_rdf_deep_free(domain_);
  }

private:
  ldns_rdf* domain_;

  friend class Query<RR_type::A>;
  friend class Query<RR_type::PTR>;
  friend class Query<RR_type::TXT>;
};

template <RR_type T>
class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver const& res, Domain const& dom)
    : p_(CHECK_NOTNULL(ldns_resolver_query(res.res_, dom.domain_,
                                           static_cast<ldns_enum_rr_type>(T),
                                           LDNS_RR_CLASS_IN, LDNS_RD)))
  {
  }
  ~Query()
  {
    ldns_pkt_free(p_);
  }

  Pkt_rcode get_rcode() const
  {
    return static_cast<Pkt_rcode>(ldns_pkt_get_rcode(p_));
  }

private:
  ldns_pkt* p_;

  friend class Rrlist<T>;
};

template <RR_type T>
class Rrlist {
public:
  Rrlist(Rrlist const&) = delete;
  Rrlist& operator=(Rrlist const&) = delete;

  explicit Rrlist(Query<T> const& q)
    : rrlst_(ldns_pkt_rr_list_by_type(q.p_, static_cast<ldns_enum_rr_type>(T),
                                      LDNS_SECTION_ANSWER))
  {
  }
  ~Rrlist()
  {
    if (!empty()) // since we don't assert success in the ctr()
      ldns_rr_list_deep_free(rrlst_);
  }
  bool empty() const
  {
    return nullptr == rrlst_;
  }

  std::vector<std::string> get() const;

private:
  ldns_rr_list* rrlst_;
};

extern std::vector<std::string>
get_loop(enum ldns_enum_rdf_type t, ldns_rr_list* rrlst,
         std::function<std::string(ldns_rdf const* rdf)> f);

template <>
inline std::vector<std::string> Rrlist<RR_type::TXT>::get() const
{
  return get_loop(LDNS_RDF_TYPE_STR, rrlst_, [](ldns_rdf const* rdf) {
    char const* data = static_cast<char const*>(rdf->_data);
    unsigned char const* udata = static_cast<unsigned char const*>(rdf->_data);

    return std::string(data + 1, static_cast<size_t>(*udata));
  });
}

template <>
inline std::vector<std::string> Rrlist<RR_type::PTR>::get() const
{
  return get_loop(LDNS_RDF_TYPE_DNAME, rrlst_, [](ldns_rdf const* rdf) {
    unsigned char* data = static_cast<unsigned char*>(rdf->_data);

    unsigned char src_pos = 0;
    unsigned char len = data[src_pos];

    if (rdf->_size > LDNS_MAX_DOMAINLEN) {
      LOG(WARNING) << "rdf size too large";
      return std::string{ "<too long>" };
    }

    std::ostringstream str;
    if (1 == rdf->_size) {
      str << '.'; // root label
    } else {
      while ((len > 0) && (src_pos < rdf->_size)) {
        src_pos++;
        for (unsigned char i = 0; i < len; ++i) {
          unsigned char c = data[src_pos];
          if (c == '.' || c == ';' || c == '(' || c == ')' || c == '\\') {
            str << '\\' << c;
          } else if (!(isascii(c) && isgraph(c))) {
            str << "0x" << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<unsigned>(c);
          } else {
            str << c;
          }
          src_pos++;
        }
        if (src_pos < rdf->_size) {
          str << '.';
        }
        len = data[src_pos];
      }
    }
    return str.str();
  });
}

template <>
inline std::vector<std::string> Rrlist<RR_type::A>::get() const
{
  return get_loop(LDNS_RDF_TYPE_A, rrlst_, [](ldns_rdf const* rdf) {
    char str[INET_ADDRSTRLEN];
    PCHECK(inet_ntop(AF_INET, rdf->_data, str, sizeof str));
    return std::string(str);
  });
}

template <RR_type T>
inline bool has_record(Resolver const& res, std::string const& addr)
{
  Domain dom(addr.c_str());
  Query<T> q(res, dom);
  Rrlist<T> rrlst(q);
  return !rrlst.empty();
}

template <RR_type T>
inline std::vector<std::string> get_records(Resolver const& res,
                                            std::string const& addr)
{
  Domain dom(addr.c_str());
  Query<T> q(res, dom);
  Rrlist<T> rrlst(q);
  return rrlst.get();
}

} // namespace DNS

#endif // DNS_DOT_HPP

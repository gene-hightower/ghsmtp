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
#include <iostream>
#include <iomanip>
#include <unordered_map>

#include <ldns/ldns.h>
#undef bool

#include <arpa/inet.h>

#include <boost/regex.hpp>
#include <boost/utility/string_ref.hpp>

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

extern std::unordered_map<Pkt_rcode, char const*> Pkt_rcode_to_string;

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

  std::string rr_name_str(ldns_rdf const* rdf) const;
  std::string rr_str(ldns_rdf const* rdf) const;
};

template <>
inline std::vector<std::string> Rrlist<RR_type::TXT>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      ldns_rr const* rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          ldns_rdf const* rdf = rr->_rdata_fields[j];
          switch (rdf->_type) {
          case LDNS_RDF_TYPE_STR:
            ret.push_back(rr_str(rdf));
            break;

          default:
            LOG(WARNING) << "expecting TXT got:"
                         << static_cast<unsigned>(rdf->_type);
            break;
          }
        }
      }
    }
  }
  return ret;
}

template <>
inline std::vector<std::string> Rrlist<RR_type::PTR>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      ldns_rr const* rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          ldns_rdf const* rdf = rr->_rdata_fields[j];
          switch (rdf->_type) {
          case LDNS_RDF_TYPE_DNAME:
            ret.push_back(rr_name_str(rdf));
            break;

          default:
            LOG(WARNING) << "expecting PTR got:"
                         << static_cast<unsigned>(rdf->_type);
            break;
          }
        }
      }
    }
  }
  return ret;
}

template <>
inline std::vector<std::string> Rrlist<RR_type::A>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < rrlst_->_rr_count; ++i) {
      ldns_rr const* rr = rrlst_->_rrs[i];
      if (rr) {
        for (unsigned j = 0; j < rr->_rd_count; ++j) {
          ldns_rdf const* rdf = rr->_rdata_fields[j];
          switch (rdf->_type) {
          case LDNS_RDF_TYPE_A:
            char str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, rdf->_data, str, sizeof str)) {
              ret.push_back(str);
            }
            break;

          default:
            LOG(WARNING) << "expecting A got:"
                         << static_cast<unsigned>(rdf->_type);
            break;
          }
        }
      }
    }
  }
  return ret;
}

template <RR_type T>
inline std::string Rrlist<T>::rr_name_str(ldns_rdf const* rdf) const
{
  unsigned char* data = static_cast<unsigned char*>(rdf->_data);

  unsigned char src_pos = 0;
  unsigned char len = data[src_pos];

  if (rdf->_size > LDNS_MAX_DOMAINLEN) {
    return "<too long>";
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
}

template <RR_type T>
inline std::string Rrlist<T>::rr_str(ldns_rdf const* rdf) const
{
  char const* data = static_cast<char const*>(rdf->_data);
  unsigned char const* udata = static_cast<unsigned char const*>(rdf->_data);

  return std::string(data + 1, static_cast<size_t>(*udata));
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

inline bool is_dotted_quad(char const* addr)
{
  constexpr char const* dotted_quad_rgx = "\\d{1,3}\\."
                                          "\\d{1,3}\\."
                                          "\\d{1,3}\\."
                                          "\\d{1,3}";

  boost::regex dotted_quad_rx(dotted_quad_rgx);
  boost::cmatch matches;
  return boost::regex_match(addr, matches, dotted_quad_rx);
}

inline std::string reverse_ip4(char const* addr)
{
  constexpr char const* dotted_quad_cap_rgx = "(\\d{1,3})\\."
                                              "(\\d{1,3})\\."
                                              "(\\d{1,3})\\."
                                              "(\\d{1,3})";

  boost::regex dotted_quad_rx(dotted_quad_cap_rgx);
  boost::cmatch matches;
  CHECK(boost::regex_match(addr, matches, dotted_quad_rx))
      << "reverse_ip4 called with bad dotted quad: " << addr;

  std::ostringstream reverse;
  for (int n = 4; n > 0; --n) {
    boost::string_ref octet(matches[n].first,
                            matches[n].second - matches[n].first);
    reverse << octet << '.'; // and leave a trailing '.'
  }
  return reverse.str();
}

} // namespace DNS

namespace std {
template <>
struct hash<DNS::Pkt_rcode> {
  size_t operator()(DNS::Pkt_rcode const& x) const
  {
    return static_cast<size_t>(x);
  }
};
}

#endif // DNS_DOT_HPP

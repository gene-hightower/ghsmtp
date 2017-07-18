#include <algorithm>
#include <iomanip>

#include "DNS.hpp"

namespace DNS {

char const* as_cstr(Pkt_rcode pkt_rcode)
{
  switch (pkt_rcode) {
  case DNS::Pkt_rcode::NOERROR:
    return "NOERROR";
  case DNS::Pkt_rcode::FORMERR:
    return "FORMERR";
  case DNS::Pkt_rcode::SERVFAIL:
    return "SERVFAIL";
  case DNS::Pkt_rcode::NXDOMAIN:
    return "NXDOMAIN";
  case DNS::Pkt_rcode::NOTIMPL:
    return "NOTIMPL";
  case DNS::Pkt_rcode::REFUSED:
    return "REFUSED";
  case DNS::Pkt_rcode::YXDOMAIN:
    return "YXDOMAIN";
  case DNS::Pkt_rcode::YXRRSET:
    return "YXRRSET";
  case DNS::Pkt_rcode::NXRRSET:
    return "NXRRSET";
  case DNS::Pkt_rcode::NOTAUTH:
    return "NOTAUTH";
  case DNS::Pkt_rcode::NOTZONE:
    return "NOTZONE";
  case DNS::Pkt_rcode::INTERNAL:
    return "INTERNAL";
  }
  return "** unknown **";
}

std::ostream& operator<<(std::ostream& os, Pkt_rcode pkt_rcode)
{
  return os << as_cstr(pkt_rcode);
}

template <>
std::vector<std::string> Rrlist<RR_type::MX>::get() const
{
  std::vector<std::string> hosts;
  std::vector<uint16_t> priorities;

  if (rrlst_) {
    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_, i);
      if (rr) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr); ++j) {
          auto const rdf = ldns_rr_rdf(rr, j);
          auto type = ldns_rdf_get_type(rdf);
          if (type == LDNS_RDF_TYPE_DNAME) {
            hosts.push_back(rr_name_str(rdf));
          }
          else if (type == LDNS_RDF_TYPE_INT16) {
            priorities.push_back(ldns_rdf2native_int16(rdf));
          }
          else {
            LOG(WARNING) << "non DNAME/INT16 for MX query: "
                         << static_cast<unsigned>(type);
          }
        }
      }
    }
  }

  // We return the vector sorted by priority, low to high.

  CHECK_EQ(hosts.size(), priorities.size());

  std::vector<int> index(priorities.size(), 0);
  for (unsigned i = 0; i != index.size(); i++) {
    index[i] = i;
  }

  std::sort(index.begin(), index.end(), [&](const int& a, const int& b) {
    return (priorities[a] < priorities[b]);
  });

  std::vector<std::string> ret;
  for (auto i : index) {
    ret.push_back(hosts[i]);
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::TXT>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_, i);
      if (rr) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr); ++j) {
          auto const rdf = ldns_rr_rdf(rr, j);
          auto type = ldns_rdf_get_type(rdf);
          if (type == LDNS_RDF_TYPE_STR) {
            ret.push_back(rr_str(rdf));
          }
          else {
            LOG(WARNING) << "expecting TXT got:" << static_cast<unsigned>(type);
          }
        }
      }
    }
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::PTR>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_, i);
      if (rr) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr); ++j) {
          auto const rdf = ldns_rr_rdf(rr, j);
          auto type = ldns_rdf_get_type(rdf);
          if (type == LDNS_RDF_TYPE_DNAME) {
            ret.push_back(rr_name_str(rdf));
          }
          else {
            LOG(WARNING) << "expecting DNAME got:"
                         << static_cast<unsigned>(type);
            break;
          }
        }
      }
    }
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::A>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_, i);
      if (rr) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr); ++j) {
          auto rdf = ldns_rr_rdf(rr, j);
          auto type = ldns_rdf_get_type(rdf);
          if (type == LDNS_RDF_TYPE_A) {
            char str[INET_ADDRSTRLEN];
            PCHECK(inet_ntop(AF_INET, ldns_rdf_data(rdf), str, sizeof str));
            ret.push_back(str);
          }
          else {
            LOG(WARNING) << "expecting A got:" << static_cast<unsigned>(type);
          }
        }
      }
    }
  }
  return ret;
}

template <>
std::vector<std::string> Rrlist<RR_type::AAAA>::get() const
{
  std::vector<std::string> ret;
  if (rrlst_) {
    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_, i);
      if (rr) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr); ++j) {
          auto const rdf = ldns_rr_rdf(rr, j);
          auto type = ldns_rdf_get_type(rdf);
          if (type == LDNS_RDF_TYPE_AAAA) {
            char str[INET6_ADDRSTRLEN];
            PCHECK(inet_ntop(AF_INET6, ldns_rdf_data(rdf), str, sizeof str));
            ret.push_back(str);
          }
          else {
            LOG(WARNING) << "expecting AAAA got:"
                         << static_cast<unsigned>(type);
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
  auto sz = ldns_rdf_size(rdf);

  if (sz > LDNS_MAX_DOMAINLEN) {
    LOG(WARNING) << "rdf size too large";
    return "<too long>";
  }
  if (sz == 1) {
    return "."; // root label
  }

  auto data = ldns_rdf_data(rdf);

  unsigned char src_pos = 0;
  unsigned char len = data[src_pos];

  std::ostringstream str;
  while ((len > 0) && (src_pos < ldns_rdf_size(rdf))) {
    src_pos++;
    for (unsigned char i = 0; i < len; ++i) {
      unsigned char c = data[src_pos];
      if (c == '.' || c == ';' || c == '(' || c == ')' || c == '\\') {
        str << '\\' << c;
      }
      else if (!(isascii(c) && isgraph(c))) {
        str << "0x" << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(c);
      }
      else {
        str << c;
      }
      src_pos++;
    }
    if (src_pos < ldns_rdf_size(rdf)) {
      str << '.';
    }
    len = data[src_pos];
  }

  return str.str();
}
}

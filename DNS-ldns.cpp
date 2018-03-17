#include "DNS-ldns.hpp"

#include <cstring>
#include <iomanip>

#include <cstdbool> // needs to be above ldns includes
#include <ldns/ldns.h>
#include <ldns/packet.h>
#include <ldns/rr.h>

#include <arpa/inet.h>

#include <glog/logging.h>

namespace DNS {

RR_A::RR_A(uint8_t const* rd, size_t sz)
{
  CHECK_EQ(sz, sizeof(addr_.sin_addr));
  std::memcpy(&addr_.sin_addr, rd, sizeof(addr_.sin_addr));
  PCHECK(inet_ntop(AF_INET, &addr_.sin_addr, str_, sizeof str_));
}

RR_AAAA::RR_AAAA(uint8_t const* rd, size_t sz)
{
  CHECK_EQ(sz, sizeof(addr_.sin6_addr));
  std::memcpy(&addr_.sin6_addr, rd, sizeof(addr_.sin6_addr));
  PCHECK(inet_ntop(AF_INET6, &addr_.sin6_addr, str_, sizeof str_));
}

std::string rr_name_str(ldns_rdf const* rdf)
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

std::string rr_str(ldns_rdf const* rdf)
{
  CHECK_NOTNULL(rdf);

  auto data = static_cast<char const*>(rdf->_data);
  auto udata = static_cast<unsigned char const*>(rdf->_data);

  return std::string(data + 1, static_cast<std::string::size_type>(*udata));
}

Resolver::Resolver()
{
  auto status = ldns_resolver_new_frm_file(&res_, nullptr);
  CHECK_EQ(status, LDNS_STATUS_OK) << "failed to initialize DNS resolver: "
                                   << ldns_get_errorstr_by_id(status);
}

Resolver::~Resolver() { ldns_resolver_deep_free(res_); }

Domain::Domain(char const* domain)
  : str_(domain)
  , drdfp_(CHECK_NOTNULL(ldns_dname_new_frm_str(domain)))
{
}

Domain::~Domain() { ldns_rdf_deep_free(drdfp_); }

Query::Query(Resolver const& res, RRtype type, Domain const& dom)
{
  ldns_status status = ldns_resolver_query_status(
      &p_, res.res_, dom.drdfp_, static_cast<ldns_enum_rr_type>(type),
      LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);

  if (status != LDNS_STATUS_OK) {
    bogus_or_indeterminate_ = true;

    LOG(WARNING) << "Query (" << dom.str_ << "/" << RRtype_c_str(type) << ") "
                 << "ldns_resolver_query_status failed: "
                 << ldns_get_errorstr_by_id(status);

    // If we have only one nameserver, reset the RTT otherwise all
    // future use of this resolver object will fail.

    if (ldns_resolver_nameserver_count(res.res_) == 1) {
      if (ldns_resolver_rtt(res.res_) == LDNS_RESOLV_RTT_INF) {
        ldns_resolver_set_nameserver_rtt(res.res_, 0,
                                         LDNS_RESOLV_RTT_MIN); // "reachable"
      }
    }
  }

  if (p_) {
    auto const rcode = ldns_pkt_get_rcode(p_);

    switch (rcode) {
    case LDNS_RCODE_NOERROR:
      break;

    case LDNS_RCODE_NXDOMAIN:
      nx_domain_ = true;
      LOG(WARNING) << "NX domain (" << dom.str_ << "/" << RRtype_c_str(type)
                   << ")";
      return;

    default:
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "DNS query (" << dom.str_ << "/" << RRtype_c_str(type)
                   << ") ldns_resolver_query_status failed: rcode=" << rcode;
      return;
    }
  }
}

Query::~Query()
{
  if (p_)
    ldns_pkt_free(p_);
}

RR_list::RR_list(Query const& q)
{
  if (q.p_) {
    // no clones, so no frees required
    rrlst_answer_ = ldns_pkt_answer(q.p_);
    rrlst_additional_ = ldns_pkt_additional(q.p_);
  }
}

RR_list::~RR_list() {}

RR_set RR_list::get() const
{
  RR_set ret;

  if (rrlst_answer_) {
    LOG(INFO) << "ldns_rr_list_rr_count(rrlst_answer_) == "
              << ldns_rr_list_rr_count(rrlst_answer_);

    ret.reserve(ldns_rr_list_rr_count(rrlst_answer_));

    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_answer_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_answer_, i);

      if (rr) {
        LOG(INFO) << "ldns_rr_rd_count(rr) == " << ldns_rr_rd_count(rr);
        LOG(INFO) << "ldns_rr_get_type(rr) == " << ldns_rr_get_type(rr);

        switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_A: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_A);
          ret.emplace_back(RR_A{ldns_rdf_data(rdf), ldns_rdf_size(rdf)});
          break;
        }
        case LDNS_RR_TYPE_CNAME: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(RR_CNAME{rr_name_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_PTR: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(RR_PTR{rr_name_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_MX: {
          CHECK_EQ(ldns_rr_rd_count(rr), 2);
          auto const rdf_0 = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf_0), LDNS_RDF_TYPE_INT16);
          auto const rdf_1 = ldns_rr_rdf(rr, 1);
          CHECK_EQ(ldns_rdf_get_type(rdf_1), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(
              RR_MX{rr_name_str(rdf_1), ldns_rdf2native_int16(rdf_0)});
          break;
        }
        case LDNS_RR_TYPE_TXT: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_STR);
          ret.emplace_back(RR_TXT{rr_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_AAAA: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_AAAA);
          ret.emplace_back(RR_AAAA{ldns_rdf_data(rdf), ldns_rdf_size(rdf)});
          break;
        }

        case LDNS_RR_TYPE_TLSA:
          LOG(WARNING) << "no code for LDNS_RR_TYPE_TLSA";
          break;

        default:
          LOG(WARNING) << "unknown RR type == " << ldns_rr_get_type(rr);
          break;
        }
      }
    }
  }

  LOG(INFO) << "check for additional RRs";
  if (rrlst_additional_) {
    LOG(INFO) << "ldns_rr_list_rr_count(rrlst_additional_) == "
              << ldns_rr_list_rr_count(rrlst_additional_);

    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_additional_); ++i) {
      auto const rr_additional = ldns_rr_list_rr(rrlst_additional_, i);

      if (rr_additional) {
        for (unsigned j = 0; j < ldns_rr_rd_count(rr_additional); ++j) {
          auto const rdf = ldns_rr_rdf(rr_additional, j);
          auto const type = ldns_rdf_get_type(rdf);
          switch (type) {
          case LDNS_RDF_TYPE_A: {
            auto arec{RR_A{ldns_rdf_data(rdf), ldns_rdf_size(rdf)}};
            LOG(INFO) << "A == " << arec.c_str();
            break;
          }
          case LDNS_RDF_TYPE_AAAA: {
            auto aaaarec{RR_AAAA{ldns_rdf_data(rdf), ldns_rdf_size(rdf)}};
            LOG(INFO) << "AAAA == " << aaaarec.c_str();
            break;
          }
          default:
            LOG(WARNING) << "non A/AAAA for MX additional section, type="
                         << static_cast<unsigned>(type);
          }
        }
      }
    }
  }

  return ret;
}

RR_set Resolver::get_records(RRtype typ, char const* domain)
{
  Domain dom(domain);
  Query q(*this, typ, dom);
  RR_list rrlst(q);
  return rrlst.get();
}

} // namespace DNS

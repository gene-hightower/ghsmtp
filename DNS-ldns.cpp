#include "DNS-ldns.hpp"

#include "DNS-iostream.hpp"

#include <algorithm>
#include <iomanip>

#include <cstdbool> // needs to be above ldns includes
#include <ldns/ldns.h>
#include <ldns/packet.h>
#include <ldns/rr.h>

#include <arpa/inet.h>

#include <glog/logging.h>

#include <fmt/format.h>

namespace DNS_ldns {

std::string rr_name_str(ldns_rdf const* rdf)
{
  auto const sz = ldns_rdf_size(rdf);

  if (sz > LDNS_MAX_DOMAINLEN) {
    LOG(WARNING) << "rdf size too large";
    return "<too long>";
  }
  if (sz == 1) {
    return ""; // root label
  }

  auto const data = ldns_rdf_data(rdf);

  unsigned char src_pos = 0;
  unsigned char len = data[src_pos];

  std::string str;
  str.reserve(64);
  while ((len > 0) && (src_pos < sz)) {
    src_pos++;
    for (unsigned char i = 0; i < len; ++i) {
      unsigned char c = data[src_pos];
      // if (c == '.' || c == ';' || c == '(' || c == ')' || c == '\\') {
      if (c == '.' || c == '\\') {
        str += '\\';
        // str += c;
      }
      // else if (!(isascii(c) && isgraph(c))) {
      //   str += fmt::format("0x{:02x}", c);
      // }
      // else {
      str += c;
      // }
      src_pos++;
    }
    if (src_pos < sz) {
      str += '.';
    }
    len = data[src_pos];
  }

  if (str.length() && ('.' == str.back())) {
    str.erase(str.length() - 1);
  }

  return str;
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
  , rdfp_(CHECK_NOTNULL(ldns_dname_new_frm_str(domain)))
{
}

Domain::Domain(std::string const& domain)
  : str_(domain)
  , rdfp_(CHECK_NOTNULL(ldns_dname_new_frm_str(domain.c_str())))
{
}

Domain::~Domain() { ldns_rdf_deep_free(rdfp_); }

Query::Query(Resolver const& res, DNS::RR_type type, std::string const& dom)
  : Query(res, type, dom.c_str())
{
}

Query::Query(Resolver const& res, DNS::RR_type type, char const* domain)
{
  Domain dom(domain);

  ldns_status status = ldns_resolver_query_status(
      &p_, res.get(), dom.get(), static_cast<ldns_enum_rr_type>(type),
      LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);

  if (status != LDNS_STATUS_OK) {
    bogus_or_indeterminate_ = true;

    // LOG(WARNING) << "Query (" << dom.str() << "/" << type << ") "
    //              << "ldns_resolver_query_status failed: "
    //              << ldns_get_errorstr_by_id(status);

    // If we have only one nameserver, reset the RTT otherwise all
    // future use of this resolver object will fail.

    ldns_resolver_set_nameserver_rtt(res.get(), 0,
                                     LDNS_RESOLV_RTT_MIN); // "reachable"
  }

  if (p_) {
    authentic_data_ = ldns_pkt_ad(p_);

    auto const rcode = ldns_pkt_get_rcode(p_);

    switch (rcode) {
    case LDNS_RCODE_NOERROR:
      break;

    case LDNS_RCODE_NXDOMAIN:
      nx_domain_ = true;
      // LOG(WARNING) << "NX domain (" << dom.str() << "/" << type << ")";
      break;

    case LDNS_RCODE_SERVFAIL:
      bogus_or_indeterminate_ = true;
      // LOG(WARNING) << "DNS server fail (" << dom.str() << "/" << type << ")";
      break;

    default:
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "DNS unknown error (" << dom.str() << "/" << type
                   << "), rcode = " << DNS::rcode_c_str(rcode) << " (" << rcode
                   << ")";
      break;
    }
  }
}

Query::~Query()
{
  if (p_)
    ldns_pkt_free(p_);
}

DNS::RR_collection Query::get_records() const
{
  RR_list rrlst(*this);
  return rrlst.get_records();
}

std::vector<std::string> Query::get_strings() const
{
  RR_list rrlst(*this);
  return rrlst.get_strings();
}

RR_list::RR_list(Query const& q)
{
  if (q.get()) {
    // no clones, so no frees required
    rrlst_answer_ = ldns_pkt_answer(q.get());
    rrlst_additional_ = ldns_pkt_additional(q.get());
  }
}

RR_list::~RR_list() {}

DNS::RR_collection RR_list::get_records() const
{
  DNS::RR_collection ret;

  if (rrlst_answer_) {

    ret.reserve(ldns_rr_list_rr_count(rrlst_answer_));

    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_answer_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_answer_, i);

      if (rr) {
        // LOG(INFO) << "ldns_rr_rd_count(rr) == " << ldns_rr_rd_count(rr);

        switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_A: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_A);
          ret.emplace_back(DNS::RR_A{ldns_rdf_data(rdf), ldns_rdf_size(rdf)});
          break;
        }
        case LDNS_RR_TYPE_CNAME: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(DNS::RR_CNAME{rr_name_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_PTR: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(DNS::RR_PTR{rr_name_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_MX: {
          CHECK_EQ(ldns_rr_rd_count(rr), 2);
          auto const rdf_0 = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf_0), LDNS_RDF_TYPE_INT16);
          auto const rdf_1 = ldns_rr_rdf(rr, 1);
          CHECK_EQ(ldns_rdf_get_type(rdf_1), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(
              DNS::RR_MX{rr_name_str(rdf_1), ldns_rdf2native_int16(rdf_0)});
          break;
        }
        case LDNS_RR_TYPE_TXT: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_STR);
          ret.emplace_back(DNS::RR_TXT{rr_str(rdf)});
          break;
        }
        case LDNS_RR_TYPE_AAAA: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_AAAA);
          ret.emplace_back(
              DNS::RR_AAAA{ldns_rdf_data(rdf), ldns_rdf_size(rdf)});
          break;
        }
        case LDNS_RR_TYPE_TLSA: {
          CHECK_EQ(ldns_rr_rd_count(rr), 4);

          auto const usage{[&] {
            auto const rdf = ldns_rr_rdf(rr, 0);
            CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_CERTIFICATE_USAGE);
            return ldns_rdf2native_int8(rdf);
          }()};

          auto const selector{[&] {
            auto const rdf = ldns_rr_rdf(rr, 1);
            CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_SELECTOR);
            return ldns_rdf2native_int8(rdf);
          }()};

          auto const matching_type{[&] {
            auto const rdf = ldns_rr_rdf(rr, 2);
            CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_MATCHING_TYPE);
            return ldns_rdf2native_int8(rdf);
          }()};

          auto const rdf = ldns_rr_rdf(rr, 3);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_HEX);

          ret.emplace_back(DNS::RR_TLSA{usage, selector, matching_type,
                                        ldns_rdf_data(rdf),
                                        ldns_rdf_size(rdf)});
          break;
        }

        default:
          LOG(WARNING) << "unknown RR type == " << ldns_rr_get_type(rr);
          break;
        }
      }
    }
  }

  if (rrlst_additional_) {
    auto const rr_count = ldns_rr_list_rr_count(rrlst_additional_);
    if (rr_count) {
      LOG(WARNING) << rr_count << " additional RR records";
      for (unsigned i = 0; i < rr_count; ++i) {
        auto const rr = ldns_rr_list_rr(rrlst_additional_, i);
        if (rr) {
          auto type = ldns_rr_get_type(rr);
          LOG(WARNING) << "additional record " << i << " type "
                       << DNS::RR_type_c_str(type);
        }
      }
    }
  }

  return ret;
}

std::vector<std::string> RR_list::get_strings() const
{
  std::vector<std::string> ret;

  if (rrlst_answer_) {

    ret.reserve(ldns_rr_list_rr_count(rrlst_answer_));

    for (unsigned i = 0; i < ldns_rr_list_rr_count(rrlst_answer_); ++i) {
      auto const rr = ldns_rr_list_rr(rrlst_answer_, i);

      if (rr) {
        // LOG(INFO) << "ldns_rr_rd_count(rr) == " << ldns_rr_rd_count(rr);

        switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_A: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_A);
          auto const a{DNS::RR_A{ldns_rdf_data(rdf), ldns_rdf_size(rdf)}};
          ret.emplace_back(a.c_str());
          break;
        }
        case LDNS_RR_TYPE_CNAME: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(rr_name_str(rdf));
          break;
        }
        case LDNS_RR_TYPE_PTR: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(rr_name_str(rdf));
          break;
        }
        case LDNS_RR_TYPE_MX: {
          CHECK_EQ(ldns_rr_rd_count(rr), 2);
          auto const rdf_0 = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf_0), LDNS_RDF_TYPE_INT16);
          auto const rdf_1 = ldns_rr_rdf(rr, 1);
          CHECK_EQ(ldns_rdf_get_type(rdf_1), LDNS_RDF_TYPE_DNAME);
          ret.emplace_back(rr_name_str(rdf_1));
          break;
        }
        case LDNS_RR_TYPE_TXT: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_STR);
          ret.emplace_back(rr_str(rdf));
          break;
        }
        case LDNS_RR_TYPE_AAAA: {
          CHECK_EQ(ldns_rr_rd_count(rr), 1);
          auto const rdf = ldns_rr_rdf(rr, 0);
          CHECK_EQ(ldns_rdf_get_type(rdf), LDNS_RDF_TYPE_AAAA);
          auto const a{DNS::RR_AAAA{ldns_rdf_data(rdf), ldns_rdf_size(rdf)}};
          ret.emplace_back(a.c_str());
          break;
        }
        default:
          LOG(WARNING) << "unknown RR type == " << ldns_rr_get_type(rr);
          break;
        }
      }
    }
  }

  return ret;
}

DNS::RR_collection Resolver::get_records(DNS::RR_type typ,
                                         char const* domain) const
{
  Query q(*this, typ, domain);
  RR_list rrlst(q);
  return rrlst.get_records();
}

std::vector<std::string> Resolver::get_strings(DNS::RR_type typ,
                                               char const* domain) const
{
  Query q(*this, typ, domain);
  RR_list rrlst(q);
  return rrlst.get_strings();
}

} // namespace DNS_ldns

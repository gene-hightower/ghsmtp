#include "DNS.hpp"

#include <glog/logging.h>

#include <ldns/packet.h>
#include <ldns/rr.h>

// Leaving bool and friends defined macros is rude in C++.  This is
// (apparently) thanks to advice from:
// <https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Particular-Headers.html>
#undef bool
#undef false
#undef true

int main(int argc, char const* argv[])
{
  using namespace DNS;

  CHECK_EQ(sizeof(DNS::Resolver), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Domain), sizeof(void*) + sizeof(std::string));
  CHECK_EQ(sizeof(DNS::Query<DNS::RR_type::A>), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Rrlist<DNS::RR_type::A>), sizeof(void*));

  // clang-format off
  CHECK(RR_type::A     == RR_type(LDNS_RR_TYPE_A));
  CHECK(RR_type::AAAA  == RR_type(LDNS_RR_TYPE_AAAA));
  CHECK(RR_type::CNAME == RR_type(LDNS_RR_TYPE_CNAME));
  CHECK(RR_type::MX    == RR_type(LDNS_RR_TYPE_MX));
  CHECK(RR_type::PTR   == RR_type(LDNS_RR_TYPE_PTR));
  CHECK(RR_type::TLSA  == RR_type(LDNS_RR_TYPE_TLSA));
  CHECK(RR_type::TXT   == RR_type(LDNS_RR_TYPE_TXT));

  CHECK(Pkt_rcode::NOERROR  == Pkt_rcode(LDNS_RCODE_NOERROR));
  CHECK(Pkt_rcode::FORMERR  == Pkt_rcode(LDNS_RCODE_FORMERR));
  CHECK(Pkt_rcode::SERVFAIL == Pkt_rcode(LDNS_RCODE_SERVFAIL));
  CHECK(Pkt_rcode::NXDOMAIN == Pkt_rcode(LDNS_RCODE_NXDOMAIN));
  CHECK(Pkt_rcode::NOTIMPL  == Pkt_rcode(LDNS_RCODE_NOTIMPL));
  CHECK(Pkt_rcode::REFUSED  == Pkt_rcode(LDNS_RCODE_REFUSED));
  CHECK(Pkt_rcode::YXDOMAIN == Pkt_rcode(LDNS_RCODE_YXDOMAIN));
  CHECK(Pkt_rcode::YXRRSET  == Pkt_rcode(LDNS_RCODE_YXRRSET));
  CHECK(Pkt_rcode::NXRRSET  == Pkt_rcode(LDNS_RCODE_NXRRSET));
  CHECK(Pkt_rcode::NOTAUTH  == Pkt_rcode(LDNS_RCODE_NOTAUTH));
  CHECK(Pkt_rcode::NOTZONE  == Pkt_rcode(LDNS_RCODE_NOTZONE));
  // clang-format on

  DNS::Resolver res;

  auto goog_a = "google-public-dns-a.google.com";
  auto goog_b = "google-public-dns-b.google.com";

  auto addrs_a = DNS::get_records<DNS::RR_type::A>(res, goog_a);
  CHECK_EQ(addrs_a.size(), 1U);
  CHECK_EQ(addrs_a[0], "8.8.8.8");

  auto addrs_b = DNS::get_records<DNS::RR_type::A>(res, goog_b);
  CHECK_EQ(addrs_b.size(), 1U);
  CHECK_EQ(addrs_b[0], "8.8.4.4");

  auto aaaaddrs_a = DNS::get_records<DNS::RR_type::AAAA>(res, goog_a);
  CHECK_EQ(aaaaddrs_a.size(), 1U);
  CHECK_EQ(aaaaddrs_a[0], "2001:4860:4860::8888");

  auto aaaaddrs_b = DNS::get_records<DNS::RR_type::AAAA>(res, goog_b);
  CHECK_EQ(aaaaddrs_b.size(), 1U);
  CHECK_EQ(aaaaddrs_b[0], "2001:4860:4860::8844");
}

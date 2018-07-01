#include "DNS-fcrdns.hpp"
#include "DNS-iostream.hpp"
#include "DNS-ldns.hpp"
#include "DNS-priv.hpp"
#include "DNS-rrs.hpp"
#include "Domain.hpp"

#include <algorithm>
#include <random>

#include <glog/logging.h>

template <typename... Ts>
std::ostream& operator<<(std::ostream& os, const std::variant<Ts...>& v)
{
  std::visit([&os](auto&& arg) { os << arg; }, v);
  return os;
}

int main(int argc, char const* argv[])
{
  DNS::Resolver res;
  DNS_ldns::Resolver res_ldns;

  struct lkp {
    DNS::RR_type typ;
    char const* name;
  };

  lkp lookups[] = {
      {DNS::RR_type::A, "amazon.com"},
      {DNS::RR_type::A, "dee.test.digilicious.com"},
      {DNS::RR_type::A, "does-not-exist.test.digilicious.com"},
      {DNS::RR_type::A, "google-public-dns-a.google.com"},
      {DNS::RR_type::A, "google-public-dns-b.google.com"},
      {DNS::RR_type::AAAA, "google-public-dns-a.google.com"},
      {DNS::RR_type::AAAA, "google-public-dns-b.google.com"},
      {DNS::RR_type::CNAME, "cname4.digilicious.com"},
      {DNS::RR_type::CNAME, "com.digilicious.in-addr.arpa"},
      {DNS::RR_type::MX, "anyold.host"},
      {DNS::RR_type::MX, "cname.test.digilicious.com"},
      {DNS::RR_type::PTR, "com.digilicious.in-addr.arpa"},
      {DNS::RR_type::PTR, "com.google.in-addr.arpa"},
      {DNS::RR_type::TLSA, "_25._tcp.digilicious.com"},
      {DNS::RR_type::TLSA, "_443._tcp.digilicious.com"},
      {DNS::RR_type::TXT, "digilicious.com"},
  };

  auto failure = false;

  for (auto const& lookup : lookups) {
    DNS::Query q(res, lookup.typ, lookup.name);
    DNS_ldns::Query q_ldns(res_ldns, lookup.typ, lookup.name);

    CHECK_EQ(q.nx_domain(), q_ldns.nx_domain());
    CHECK_EQ(q.bogus_or_indeterminate(), q_ldns.bogus_or_indeterminate());

    CHECK_EQ(q.authentic_data(), q_ldns.authentic_data());

    auto const rrs{q.get_records()};
    auto const rrs_ldns{q_ldns.get_records()};

    CHECK_EQ(rrs.size(), rrs_ldns.size());

    for (auto i = 0U; i < rrs.size(); ++i) {
      if (!(rrs[i] == rrs_ldns[i])) {
        LOG(ERROR) << i << " data element from " << lookup.name << "/"
                   << lookup.typ;
        LOG(ERROR) << rrs[i] << " != " << rrs_ldns[i];
        failure = true;
      }
    }
  }

  CHECK(!failure);

  // These IP addresses might be stable for a while.

  auto goog_a{"google-public-dns-a.google.com"};
  auto goog_b{"google-public-dns-b.google.com"};

  auto addrs_b = res.get_strings(DNS::RR_type::A, goog_b);
  CHECK_EQ(addrs_b.size(), 1U);
  CHECK_EQ(addrs_b[0], "8.8.4.4");

  auto aaaaddrs_a = res.get_strings(DNS::RR_type::AAAA, goog_a);
  CHECK_EQ(aaaaddrs_a.size(), 1U);
  CHECK_EQ(aaaaddrs_a[0], "2001:4860:4860::8888");

  auto aaaaddrs_b = res.get_strings(DNS::RR_type::AAAA, goog_b);
  CHECK_EQ(aaaaddrs_b.size(), 1U);
  CHECK_EQ(aaaaddrs_b[0], "2001:4860:4860::8844");

  auto fcrdnses4 = fcrdns4(res, "1.1.1.1");
  CHECK_EQ(fcrdnses4.size(), 1);
  CHECK(Domain::match(fcrdnses4.front(), "1dot1dot1dot1.cloudflare-dns.com."))
      << "no match for " << fcrdnses4.front();

  auto fcrdnses6 = fcrdns6(res, "2606:4700:4700::1111");
  CHECK_EQ(fcrdnses6.size(), 1);
  CHECK(Domain::match(fcrdnses6.front(), "1dot1dot1dot1.cloudflare-dns.com."))
      << "no match for " << fcrdnses6.front();

  auto quad9 = fcrdns4(res, "9.9.9.9");
  CHECK(Domain::match(quad9.front(), "dns.quad9.net"))
      << "no match for " << quad9.front();
}

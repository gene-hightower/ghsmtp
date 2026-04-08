#include "DNS-fcrdns.hpp"
#include "DNS-iostream.hpp"
#include "DNS-ldns.hpp"
#include "DNS.hpp"
#include "Domain.hpp"
#include "osutil.hpp"

#include <algorithm>
#include <thread>
#include <vector>

#include <glog/logging.h>

template <typename... Ts>
std::ostream& operator<<(std::ostream& os, const std::variant<Ts...>& v)
{
  std::visit([&os](auto&& arg) { os << arg; }, v);
  return os;
}

struct lkp {
  DNS::RR_type typ;
  std::string  name;
};

// Check our resolver vs. ldns lookup.

void do_lookup(lkp const& lookup)
{
  DNS_ldns::Resolver res_ldns;

  auto const    config_path = osutil::get_config_dir();
  DNS::Resolver res(config_path);

  DNS::Query      q(res, lookup.typ, lookup.name.c_str());
  DNS_ldns::Query q_ldns(res_ldns, lookup.typ, lookup.name.c_str());

  CHECK_EQ(q.nx_domain(), q_ldns.nx_domain()) << lookup.name;

  CHECK_EQ(q.bogus_or_indeterminate(), q_ldns.bogus_or_indeterminate())
      << lookup.name;

  if (q.authentic_data() != q_ldns.authentic_data()) {
    LOG(WARNING) << "q.authentic_data() != q_ldns.authentic_data() for "
                 << lookup.name;
    LOG(WARNING) << "q.authentic_data()      == " << q.authentic_data();
    LOG(WARNING) << "q_ldns.authentic_data() == " << q_ldns.authentic_data();
  }

  auto rrs{q.get_records()};
  auto rrs_ldns{q_ldns.get_records()};

  std::sort(begin(rrs), end(rrs));
  std::sort(begin(rrs_ldns), end(rrs_ldns));

  if (size(rrs) != size(rrs_ldns)) {
    if (size(rrs) < size(rrs_ldns)) {
      LOG(WARNING) << "ldns has additional RRs:";
      for (auto rr_ldns : rrs_ldns) {
        LOG(WARNING) << rr_ldns;
      }
    }
    else { // size(rrs) > size(rrs_ldns)
      LOG(INFO) << "DNS has additional RRs:";
      for (auto rr : rrs) {
        LOG(WARNING) << rr;
      }
    }
  }
  else { // same size, compare each
    auto [rr, rr_ldns] =
        std::mismatch(begin(rrs), end(rrs), begin(rrs_ldns), end(rrs_ldns));
    if (rr != end(rrs)) {
      LOG(WARNING) << *rr << " != " << *rr_ldns;
    }
  }
}

struct lkp_result {
  DNS::RR_type typ;
  std::string  name;
  std::string  result;
};

void do_lookup_result(lkp_result const& lookup)
{
  auto const    config_path = osutil::get_config_dir();
  DNS::Resolver res(config_path);
  auto const result_strings{res.get_strings(lookup.typ, lookup.name.c_str())};
  CHECK_EQ(result_strings.size(), 1U);
  CHECK_EQ(result_strings[0], lookup.result);
}

int main(int argc, char const* argv[])
{
  auto const config_path = osutil::get_config_dir();

  lkp lookups[]{
      {DNS::RR_type::A, "amazon.com"},
      // This checks for CNAME loop
      // {DNS::RR_type::A, "dee.test.digilicious.com"},
      {DNS::RR_type::A, "does-not-exist.test.digilicious.com"},
      {DNS::RR_type::A, "google-public-dns-a.google.com"},
      {DNS::RR_type::A, "google-public-dns-b.google.com"},
      {DNS::RR_type::AAAA, "google-public-dns-a.google.com"},
      {DNS::RR_type::AAAA, "google-public-dns-b.google.com"},
      {DNS::RR_type::CNAME, "cname4.digilicious.com"},
      {DNS::RR_type::MX, "anyold.host"},
      {DNS::RR_type::MX, "cname.test.digilicious.com"},
      {DNS::RR_type::TLSA, "_25._tcp.digilicious.com"},
      {DNS::RR_type::TLSA, "_443._tcp.digilicious.com"},
      {DNS::RR_type::TXT, "digilicious.com"},
  };

  std::vector<std::thread> lookup_threads;
  for (auto const& lookup : lookups) {
    lookup_threads.emplace_back(do_lookup, lookup);
    // LOG(INFO) << lookup.name << " on thead " << lookup_threads.back().get_id();
  }
  for (auto& thread : lookup_threads) {
    // LOG(INFO) << "join " << thread.get_id();
    thread.join();
  }

  lkp_result results[]{
      {DNS::RR_type::AAAA, "google-public-dns-a.google.com",
       "2001:4860:4860::8888"},
      {DNS::RR_type::AAAA, "google-public-dns-b.google.com",
       "2001:4860:4860::8844"},

      {DNS::RR_type::A, "google-public-dns-a.google.com", "8.8.8.8"},
      {DNS::RR_type::A, "google-public-dns-b.google.com", "8.8.4.4"},
  };

  std::vector<std::thread> result_threads;
  for (auto const& lookup : results) {
    result_threads.emplace_back(do_lookup_result, lookup);
    // LOG(INFO) << lookup.name << " on thead " << result_threads.back().get_id();
  }
  for (auto& thread : result_threads) {
    // LOG(INFO) << "join " << thread.get_id();
    thread.join();
  }

  {
    DNS::Resolver res(config_path);
    auto const    one{fcrdns4(res, "1.1.1.1")};
    CHECK_EQ(one.front(), "one.one.one.one") << "no match for " << one.front();
  }
  {
    DNS::Resolver res(config_path);
    auto const    one{fcrdns4(res, "1.0.0.1")};
    CHECK_EQ(one.front(), "one.one.one.one") << "no match for " << one.front();
  }
  {
    DNS::Resolver res(config_path);
    auto const    one{fcrdns6(res, "2606:4700:4700::1111")};
    CHECK_EQ(one.front(), "one.one.one.one") << "no match for " << one.front();
  }
  {
    DNS::Resolver res(config_path);
    auto const    one{fcrdns6(res, "2606:4700:4700::1001")};
    CHECK_EQ(one.front(), "one.one.one.one") << "no match for " << one.front();
  }
  {
    DNS::Resolver res(config_path);
    auto const    quad9{fcrdns4(res, "9.9.9.9")};
    CHECK_EQ(quad9.front(), "dns9.quad9.net")
        << "no match for " << quad9.front();
  }
}

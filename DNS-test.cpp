#include "DNS.hpp"

#include <algorithm>
#include <random>

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  using namespace DNS;

  DNS::Resolver res;

  auto goog_a{"google-public-dns-a.google.com"};
  auto goog_b{"google-public-dns-b.google.com"};

  auto addrs_a = res.get_records(RR_type::A, goog_a);

  CHECK_EQ(addrs_a.size(), 1U);
  CHECK_EQ(strcmp(std::get<RR_A>(addrs_a[0]).c_str(), "8.8.8.8"), 0);

  auto addrs_b = res.get_records(RR_type::A, goog_b);
  CHECK_EQ(addrs_b.size(), 1U);
  CHECK_EQ(strcmp(std::get<RR_A>(addrs_b[0]).c_str(), "8.8.4.4"), 0);

  auto aaaaddrs_a = res.get_records(RR_type::AAAA, goog_a);
  CHECK_EQ(aaaaddrs_a.size(), 1U);
  CHECK_EQ(
      strcmp(std::get<RR_AAAA>(aaaaddrs_a[0]).c_str(), "2001:4860:4860::8888"),
      0);

  auto aaaaddrs_b = res.get_records(RR_type::AAAA, goog_b);
  CHECK_EQ(aaaaddrs_b.size(), 1U);
  CHECK_EQ(
      strcmp(std::get<RR_AAAA>(aaaaddrs_b[0]).c_str(), "2001:4860:4860::8844"),
      0);

  auto mxes = res.get_records(RR_type::MX, "anyold.host");

  // RFC 5321 section 5.1 “Locating the Target Host”
  std::shuffle(mxes.begin(), mxes.end(), std::default_random_engine());
  std::sort(mxes.begin(), mxes.end(), [](RR const& a, RR const& b) {
    if (std::holds_alternative<RR_MX>(a) && std::holds_alternative<RR_MX>(b)) {
      return std::get<RR_MX>(a).preference() < std::get<RR_MX>(b).preference();
    }
    LOG(WARNING) << "non MX records in answer section";
    return false;
  });

  for (auto const& mx : mxes) {
    LOG(INFO) << "mx.preference == " << std::get<RR_MX>(mx).preference();
    LOG(INFO) << "mx.exchange   == " << std::get<RR_MX>(mx).exchange();
  }

  auto as = res.get_records(RR_type::A, "amazon.com");
  for (auto const& a : as) {
    LOG(INFO) << "a   == " << std::get<RR_A>(a).c_str();
  }

  Query q(res, RR_type::TLSA, "_25._tcp.digilicious.com");
  CHECK(q.authentic_data()) << "TLSA records must be authenticated";
  RR_list rrlst(q);
  auto tlsas = rrlst.get_records();

  for (auto const& tlsa : tlsas) {
    unsigned usage = std::get<RR_TLSA>(tlsa).cert_usage();
    unsigned selector = std::get<RR_TLSA>(tlsa).selector();
    unsigned mtype = std::get<RR_TLSA>(tlsa).matching_type();

    // LOG(INFO) << "tlsa usage     == " << usage;
    // LOG(INFO) << "tlsa selector  == " << selector;
    // LOG(INFO) << "tlsa mtype     == " << mtype;
  }

  Query q_noexist(res, RR_type::A, "does-not-exist.test.digilicious.com");
  CHECK(q_noexist.nx_domain());
  CHECK(!q_noexist.bogus_or_indeterminate());

  Query q_dee(res, RR_type::A, "dee.test.digilicious.com");
  CHECK(!q_dee.nx_domain());
  CHECK(q_dee.bogus_or_indeterminate());

  auto cmxes = res.get_records(RR_type::MX, "cname.test.digilicious.com");
  for (auto const& cmx : cmxes) {
    if (std::holds_alternative<RR_CNAME>(cmx)) {
      LOG(INFO) << "cname == " << std::get<RR_CNAME>(cmx).str();
    }
    else {
      LOG(INFO) << "mx.preference == " << std::get<RR_MX>(cmx).preference();
      LOG(INFO) << "mx.exchange   == " << std::get<RR_MX>(cmx).exchange();
    }
  }
}

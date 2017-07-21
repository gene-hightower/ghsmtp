#include "DNS.hpp"

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  CHECK_EQ(sizeof(DNS::Resolver), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Domain), sizeof(void*) + sizeof(std::string));
  CHECK_EQ(sizeof(DNS::Query<DNS::RR_type::A>), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Rrlist<DNS::RR_type::A>), sizeof(void*));

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

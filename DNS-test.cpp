#include "DNS.hpp"

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK_EQ(sizeof(DNS::Resolver), sizeof(void*));
  // CHECK_EQ(sizeof(DNS::Domain), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Query<DNS::RR_type::A>), sizeof(void*));
  CHECK_EQ(sizeof(DNS::Rrlist<DNS::RR_type::A>), sizeof(void*));

  DNS::Resolver res;
  std::vector<std::string> addrs
      = DNS::get_records<DNS::RR_type::A>(res, "digilicious.com");

  CHECK_EQ(addrs.size(), 1U);
  CHECK_EQ(addrs[0], "108.83.36.113");
}

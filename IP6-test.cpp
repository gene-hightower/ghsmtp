#include "IP6.hpp"

#include <glog/logging.h>

#include <boost/asio/ip/address.hpp>

#include <iostream>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CHECK(IP6::is_address("::1"));
  CHECK(IP6::is_address_literal("[IPv6:::1]"));

  CHECK(IP6::is_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
  CHECK(IP6::is_address_literal("[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]"));

}

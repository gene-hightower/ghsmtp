#include "IP6.hpp"

#include <glog/logging.h>

#include <boost/asio/ip/address.hpp>

#include <iostream>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  auto as = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";

  boost::system::error_code ec;
  boost::asio::ip::address ad = boost::asio::ip::address::from_string(as, ec);

  std::cout << ad.to_string() << '\n';
}

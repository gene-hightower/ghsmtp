#include "Mailbox.hpp"

#include <iostream>

#include <glog/logging.h>

#include <boost/lexical_cast.hpp>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Mailbox mb;
  CHECK(mb.empty());

  Mailbox dg{"gene", "digilicious.com"};

  CHECK_EQ(std::string("digilicious.com"), dg.domain().ascii());

  std::string dgstr = boost::lexical_cast<std::string>(dg);

  CHECK_EQ(dgstr, "gene@digilicious.com");

  dg.clear();
  CHECK(dg.empty());

  std::cout << "sizeof(Mailbox) == " << sizeof(Mailbox) << '\n';
}

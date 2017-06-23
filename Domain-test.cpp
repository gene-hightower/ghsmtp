#include "Domain.hpp"

#include <iostream>

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  std::string d{"example.com."};

  CHECK(Domain::match(d, "EXAMPLE.COM"));
  CHECK(Domain::match(d, "example.com"));
  CHECK(Domain::match(d, "example.com."));

  CHECK(!Domain::match(d, "example.co"));
  CHECK(!Domain::match(d, "example.com.."));
  CHECK(!Domain::match(d, ""));
  CHECK(!Domain::match(d, "."));

  std::string d3{""};

  CHECK(Domain::match(d3, ""));
  CHECK(Domain::match(d3, "."));

  CHECK(!Domain::match(d3, "example.com"));

  Domain dom{"example.com"};
  CHECK_EQ(dom, Domain("EXAMPLE.COM"));

  Domain dom2{"黒川.日本"};
  Domain dom3{"xn--5rtw95l.xn--wgv71a"};
  CHECK_EQ(dom2, dom3);

  Domain poop1{"💩.la"};
  Domain poop2{"xn--ls8h.la"};
  CHECK_EQ(poop1, poop2);

  Domain norm0{"hi⒌com"};
  Domain norm1{"hi5.com"};
  CHECK_EQ(norm0, norm1);

  try {
    Domain junk{"$?%^&*("};
    // idn2 allows this
    // LOG(FATAL) << "should have thrown";
  }
  catch (std::exception const& ex) {
    // std::cout << ex.what() << '\n';
  }

  try {
    Domain ip_addr{"[127.0.0.1]"};
  }
  catch (std::exception const& ex) {
    LOG(FATAL) << "should not throw " << ex.what();
  }
}

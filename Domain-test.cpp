#include "Domain.hpp"

#include <iostream>

#include <glog/logging.h>

int main(int argc, char const* argv[])
{
  std::string const d{"example.com."};

  CHECK(Domain::match(d, "EXAMPLE.COM"));
  CHECK(Domain::match(d, "example.com."));

  CHECK(!Domain::match(d, "example.co"));
  CHECK(!Domain::match(d, "example.com.."));
  CHECK(!Domain::match(d, ""));
  CHECK(!Domain::match(d, "."));

  std::string const d3{""};

  CHECK(Domain::match(d3, ""));
  CHECK(Domain::match(d3, "."));

  CHECK(!Domain::match(d3, "example.com"));

  Domain const dom{"example.com"};
  CHECK_EQ(dom, Domain("EXAMPLE.COM"));

  Domain const dom2{"黒川.日本"};
  Domain const dom3{"xn--5rtw95l.xn--wgv71a"};
  CHECK_EQ(dom2, dom3);

  Domain const poop1{"💩.la"};
  Domain const poop2{"xn--ls8h.la"};
  CHECK_EQ(poop1, poop2);

  Domain const norm0{"hi⒌com"}; // non-ascii "dot" before "com"
  Domain const norm1{"hi5.com"};

  CHECK_EQ(norm0, norm1);

  CHECK(Domain::validate("hi⒌com"));
  CHECK(Domain::validate("hi5.com"));

  // FIXME
  // CHECK(!Domain::validate("$?%^&*("));

  try {
    Domain const junk{"$?%^&*("};
    // idn2 allows this
    // LOG(FATAL) << "should have thrown";
  }
  catch (std::exception const& ex) {
    std::cout << ex.what() << '\n';
  }

  try {
    Domain const ip_addr{"[127.0.0.1]"};
    CHECK(ip_addr.is_address_literal());
  }
  catch (std::exception const& ex) {
    LOG(FATAL) << "should not throw " << ex.what();
  }

  try {
    Domain const ip_addr{"127.0.0.1"};
    CHECK(ip_addr.is_address_literal());
  }
  catch (std::exception const& ex) {
    LOG(FATAL) << "should not throw " << ex.what();
  }

  Domain const mixed_case{"ExAmPle.COM"};
  CHECK_EQ(mixed_case.ascii(), "example.com");

  for (auto arg{1}; arg < argc; ++arg) {
    Domain const a{argv[arg]};
    std::cout << a << '\n';
  }
}

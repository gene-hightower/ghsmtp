#include "Domain.hpp"

#include <iostream>

#include <glog/logging.h>

using namespace std::string_literals;

int main(int argc, char const* argv[])
{
  std::string msg;

  auto const raw_ips = "123.123.123.123";
  auto const add_lit = "[123.123.123.123]";
  CHECK_EQ(Domain{raw_ips}, Domain{add_lit});

  Domain d0{"EXAMPLE.COM"};
  Domain d1{"example.com."};
  CHECK_EQ(d0, d1);

  Domain const d3{""};
  Domain const d4{"."};
  CHECK_EQ(d3, d4);

  Domain const dom2{"黒川.日本"};
  Domain const dom3{"xn--5rtw95l.xn--wgv71a"};
  CHECK_EQ(dom2, dom3);

  Domain const poop1{"💩.la"};
  Domain const poop2{"xn--ls8h.la"};
  CHECK_EQ(poop1, poop2);

  Domain const norm0{"hi⒌com"}; // non-ascii "dot" before "com"
  Domain const norm1{"hi5.com"};
  CHECK_EQ(norm0, norm1);

  Domain dom;
  CHECK(Domain::validate("hi⒌com", msg, dom));
  CHECK(Domain::validate("hi5.com", msg, dom));

  CHECK(!Domain::validate("$?%^&*(", msg, dom));
  CHECK_EQ(msg, "failed to parse domain «$?%^&*(»"s);

  CHECK(!Domain::validate("email@123.123.123.123", msg, dom));
  CHECK_EQ(msg, "failed to parse domain «email@123.123.123.123»"s);

  CHECK(!Domain::validate("email@[123.123.123.123]", msg, dom));
  CHECK_EQ(msg, "failed to parse domain «email@[123.123.123.123]»"s);

  auto constexpr long_dom =
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  CHECK(Domain::validate(long_dom, msg, dom)) << msg;

  CHECK(!Domain::validate(
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com",
      msg, dom));
  CHECK_EQ(msg,
           "domain name "
           "«xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
           "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
           "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
           "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com» "
           "too long");

  CHECK(!Domain::validate(
      "a.b.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "com",
      msg, dom));
  CHECK_EQ(
      msg,
      "domain label «xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx» too long"s);

  CHECK(!Domain::validate(
      "💩.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com",
      msg, dom));
  CHECK_EQ(
      msg,
      "domain label «💩.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com» too long"s);

  CHECK(!Domain::validate(
      "💩."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      msg, dom));
  CHECK_EQ(
      msg,
      "domain name «"
      "💩."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx» too long"s);

  try {
    Domain const junk{"$?%^&*("};
    // idn2 allows this
    LOG(FATAL) << "should have thrown";
  }
  catch (std::exception const& ex) {
    CHECK_EQ(0, strcmp(ex.what(), "failed to parse domain"));
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

  CHECK_EQ(Domain{"127.0.0.1"}, Domain{"[127.0.0.1]"});

  Domain const mixed_case{"ExAmPle.COM"};
  CHECK_EQ(mixed_case.ascii(), "example.com");

  CHECK(domain::is_fully_qualified(Domain{"foo.bar"}, msg));

  CHECK(!domain::is_fully_qualified(Domain{"foo.b"}, msg));
  CHECK_EQ(msg, "TLD «b» must be two or more octets");

  CHECK(!domain::is_fully_qualified(Domain{"foo"}, msg));
  CHECK_EQ(msg, "domain «foo» must have two or more labels");

  for (auto arg{1}; arg < argc; ++arg) {
    Domain const a{argv[arg]};
    std::cout << a << '\n';
  }
}

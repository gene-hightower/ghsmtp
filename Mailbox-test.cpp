#include "Mailbox.hpp"

#include <iostream>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

template <>
struct fmt::formatter<Mailbox> : ostream_formatter {};

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  CHECK_EQ(Mailbox{"\"a.b\"@foo.bar"}, Mailbox{"a.b@foo.bar"});
  CHECK_EQ(Mailbox{"\"a..b\"@foo.bar"}, Mailbox{"\"\\a\\.\\.\\b\"@foo.bar"});

  CHECK_EQ(Mailbox{"pOsTmAsTeR"}, Mailbox{"postmaster"});

  Mailbox mb;
  CHECK(mb.empty());

  Mailbox dg0{"gene@digilicious.com"};
  Mailbox dg1{"gene", Domain{"digilicious.com"}};

  CHECK_EQ(dg0, dg1);

  CHECK_EQ(std::string("digilicious.com"), dg0.domain().ascii());

  auto dgstr = static_cast<std::string>(dg0);

  CHECK_EQ(dgstr, "gene@digilicious.com");

  dg0.clear();
  CHECK(dg0.empty());

  auto threw = false;
  try {
    Mailbox bad("should throw@example.com");
  }
  catch (std::exception& e) {
    threw = true;
  }
  CHECK(threw);

  std::string msg;
  Mailbox     mbx;
  CHECK(Mailbox::validate("simple@example.com", msg, mbx));
  CHECK(Mailbox::validate("very.common@example.com", msg, mbx));
  CHECK(Mailbox::validate("disposable.style.email.with+symbol@example.com", msg,
                          mbx));
  CHECK(Mailbox::validate("other.email-with-hyphen@example.com", msg, mbx));
  CHECK(Mailbox::validate("fully-qualified-domain@example.com", msg, mbx));

  // (may go to user.name@example.com inbox depending on mail server)
  CHECK(Mailbox::validate("user.name+tag+sorting@example.com", msg, mbx));

  CHECK(Mailbox::validate("x@example.com", msg, mbx));
  CHECK(Mailbox::validate("example-indeed@strange-example.com", msg, mbx));

  CHECK(Mailbox::validate("example@s.example", msg, mbx));

  // (space between the quotes)
  CHECK(Mailbox::validate("\" \"@example.org", msg, mbx));

  // (quoted angle brackets)
  CHECK(Mailbox::validate("\"\\<foo-bar\\>\"@example.org", msg, mbx));

  // (quoted double dot)
  CHECK(Mailbox::validate("\"john..doe\"@example.org", msg, mbx));

  // (bangified host route used for uucp mailers)
  CHECK(Mailbox::validate("mailhost!username@example.org", msg, mbx));

  // (% escaped mail route to user@example.com via example.org)
  CHECK(Mailbox::validate("user%example.com@example.org", msg, mbx));

  // Invalid email addresses

  CHECK(!Mailbox::validate("Abc.example.com", msg, mbx)); // (no @ character)
  CHECK_EQ(msg, "invalid mailbox syntax «Abc.example.com»"s);

  CHECK(!Mailbox::validate("A@b@c@example.com", msg, mbx)); // (only one @ is
                                                            // allowed)
  CHECK_EQ(msg, "invalid mailbox syntax «A@b@c@example.com»"s);

  // (none of the special characters in this local-part are allowed
  // outside quotation marks)
  CHECK(!Mailbox::validate("a\"b(c)d,e:f;g<h>i[j\\k]l@example.com", msg, mbx));
  CHECK_EQ(msg,
           "invalid mailbox syntax «a\"b(c)d,e:f;g<h>i[j\\k]l@example.com»"s);

  // (quoted strings must be dot separated or the only element making
  // up the local-part)
  CHECK(!Mailbox::validate("just\"not\"right@example.com", msg, mbx));
  CHECK_EQ(msg, "invalid mailbox syntax «just\"not\"right@example.com»"s);

  // (spaces, quotes, and backslashes may only exist when within
  // quoted strings and preceded by a backslash)
  CHECK(!Mailbox::validate("this is\"not\\allowed@example.com", msg, mbx));
  CHECK_EQ(msg, "invalid mailbox syntax «this is\"not\\allowed@example.com»"s);

  // (even if escaped (preceded by a backslash), spaces, quotes, and
  // backslashes must still be contained by quotes)
  CHECK(!Mailbox::validate("this\\ still\\\"not\\\\allowed@example.com", msg,
                           mbx));
  CHECK_EQ(
      msg,
      "invalid mailbox syntax «this\\ still\\\"not\\\\allowed@example.com»"s);

  // (local part is longer than 64 characters)
  // Real world local-parts often longer than "offical" limit.
  // CHECK(!Mailbox::validate(
  //     "1234567890123456789012345678901234567890123456789012345"
  //     "678901234+x@example.com"));

  // Not fully qualified
  Mailbox foobar{"foo@bar"};
  CHECK(Mailbox::validate(foobar.as_string(Mailbox::domain_encoding::ascii),
                          msg, mbx));
  CHECK(!domain::is_fully_qualified(foobar.domain(), msg));
  CHECK_EQ(msg, "domain «bar» must have two or more labels"s);

  // TLD too short, but okay at this level.
  Mailbox foobarx{"foo@bar.x"};
  CHECK(Mailbox::validate(foobarx.as_string(Mailbox::domain_encoding::ascii),
                          msg, mbx));
  CHECK(!domain::is_fully_qualified(foobarx.domain(), msg));
  CHECK_EQ(msg, "TLD «x» must be two or more octets"s);

  // Label longer than 64 octets.
  CHECK(!Mailbox::validate(
      "foo@12345678901234567890123456789012345678901234567890123456789012345."
      "com",
      msg, mbx));
  CHECK_EQ(
      msg,
      "domain label «12345678901234567890123456789012345678901234567890123456789012345» too long"s);

  // Total domain length too long.
  CHECK(!Mailbox::validate(
      "foo@"
      "123456789012345678901234567890123456789012345678901234567890123."
      "123456789012345678901234567890123456789012345678901234567890123."
      "123456789012345678901234567890123456789012345678901234567890123."
      "123456789012345678901234567890123456789012345678901234567890123."
      "com",
      msg, mbx));
  CHECK_EQ(msg,
           "domain name «"
           "123456789012345678901234567890123456789012345678901234567890123."
           "123456789012345678901234567890123456789012345678901234567890123."
           "123456789012345678901234567890123456789012345678901234567890123."
           "123456789012345678901234567890123456789012345678901234567890123."
           "com» too long"s);

  CHECK(Mailbox::validate("gene@digilicious.com", msg, mbx));
  CHECK(Mailbox::validate("gene@[127.0.0.1]", msg, mbx));
  CHECK(!Mailbox::validate("gene@[127.999.0.1]", msg, mbx));
  CHECK_EQ(msg, "invalid mailbox syntax «gene@[127.999.0.1]»"s);
  CHECK(!Mailbox::validate("allen@bad_d0main.com", msg, mbx));
  CHECK_EQ(msg, "invalid mailbox syntax «allen@bad_d0main.com»"s);

  {
    auto const res = Mailbox::parse("gene@[127.0.0.1]");
    CHECK(res && res->local_type == Mailbox::local_types::dot_string);
    CHECK(res && res->domain_type == Mailbox::domain_types::address_literal);
  }
  {
    auto const res = Mailbox::parse("\"some string\"@example.com");
    CHECK(res && res->local_type == Mailbox::local_types::quoted_string);
    CHECK(res && res->domain_type == Mailbox::domain_types::domain);
  }

  CHECK(!Mailbox::validate("2962", msg, mbx));
  CHECK_EQ(msg, "invalid mailbox syntax «2962»"s);

  CHECK(Mailbox::validate("실례@실례.테스트", msg, mbx));

  // <https://docs.microsoft.com/en-us/archive/blogs/testing123/email-address-test-cases>

  // Valid email addresses:
  CHECK(Mailbox::validate("email@domain.com", msg, mbx));

  // Email contains dot in the local part, a dot-atom-string.
  CHECK(Mailbox::validate("firstname.lastname@domain.com", msg, mbx));

  // Multiple labels in domain.
  CHECK(Mailbox::validate("email@subdomain.domain.com", msg, mbx));

  // Plus sign is a valid character.
  CHECK(Mailbox::validate("firstname+lastname@domain.com", msg, mbx));

  // Domain is valid IP address, but this is matched as a domain.
  auto const raw_ips = "email@123.123.123.123";
  CHECK(Mailbox::validate(raw_ips, msg, mbx));

  // Square bracket around IP address is a "address literal."
  auto const add_lit = "email@[123.123.123.123]";
  CHECK(Mailbox::validate(add_lit, msg, mbx));

  CHECK_EQ(Mailbox{raw_ips}, Mailbox{add_lit});

  // Quotes around local part is valid.
  CHECK(Mailbox::validate("\"email\"@domain.com", msg, mbx));

  // But same mailbox.
  CHECK_EQ(Mailbox{"\"email\"@domain.com"}, Mailbox{"email@domain.com"});

  // Digits in address are valid.
  CHECK(Mailbox::validate("1234567890@domain.com", msg, mbx));

  // Dash in domain name is valid.
  CHECK(Mailbox::validate("email@domain-one.com", msg, mbx));

  // Underscore in the address field is valid.
  CHECK(Mailbox::validate("_______@domain.com", msg, mbx));

  CHECK(Mailbox::validate("email@domain.name", msg, mbx));
  CHECK(Mailbox::validate("email@domain.co.jp", msg, mbx));

  // Dash in local part is valid.
  CHECK(Mailbox::validate("firstname-lastname@domain.com", msg, mbx));

  CHECK(!Mailbox::validate("plainaddress", msg, mbx));     // Missing @ sign and
                                                           // domain
  CHECK(!Mailbox::validate("#@%^%#$@#$@#.com", msg, mbx)); // Garbage
  CHECK(!Mailbox::validate("@domain.com", msg, mbx));      // Missing username

  CHECK(!Mailbox::validate("Joe Smith <email@domain.com>", msg, mbx));

  CHECK(!Mailbox::validate("email.domain.com", msg, mbx));        // Missing @
  CHECK(!Mailbox::validate("email@domain@domain.com", msg, mbx)); // Two @ sign

  // Leading dot in address is not allowed
  CHECK(!Mailbox::validate(".email@domain.com", msg, mbx));

  // Trailing dot in address is not allowed
  CHECK(!Mailbox::validate("email.@domain.com", msg, mbx));

  // Multiple dots
  CHECK(!Mailbox::validate("email..email@domain.com", msg, mbx));

  // OK! Unicode char as address
  CHECK(Mailbox::validate("あいうえお@domain.com", msg, mbx));

  // Comment not allowed in 5321 mailbox.
  CHECK(!Mailbox::validate("email@domain.com (Joe Smith)", msg, mbx));

  // Missing top level domain (.com/.net/.org/etc).
  CHECK(Mailbox::validate("email@domain", msg, mbx)) << msg;

  // Leading dash in front of domain is invalid.
  CHECK(!Mailbox::validate("email@-domain.com", msg, mbx));

  // .web is not a valid top level domain, oh yeah? says who?
  CHECK(Mailbox::validate("email@domain.web", msg, mbx));

  // Invalid IP address.
  CHECK(!Mailbox::validate("email@[111.222.333.44444]", msg, mbx));

  // Invalid IP address, but valid domain name as it turns out.
  CHECK(Mailbox::validate("email@111.222.333.44444", msg, mbx));

  // Not a valid domain name.
  CHECK(!Mailbox::validate("email@domain..com", msg, mbx));

  // general_address_literal
  CHECK(!Mailbox::validate("email@[x:~Foo_Bar_Baz<\?\?>]", msg, mbx));

  std::cout << "sizeof(Mailbox) == " << sizeof(Mailbox) << '\n';
}

#include "Mailbox.hpp"

#include <iostream>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  Mailbox postmaster("postmaster@[127.0.0.1]");

  Mailbox mb;
  CHECK(mb.empty());

  Mailbox dg0{"gene@digilicious.com"};
  Mailbox dg1{"gene", "digilicious.com"};

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

  CHECK(Mailbox::validate("simple@example.com"));
  CHECK(Mailbox::validate("very.common@example.com"));
  CHECK(Mailbox::validate("disposable.style.email.with+symbol@example.com"));
  CHECK(Mailbox::validate("other.email-with-hyphen@example.com"));
  CHECK(Mailbox::validate("fully-qualified-domain@example.com"));

  // (may go to user.name@example.com inbox depending on mail server)
  CHECK(Mailbox::validate("user.name+tag+sorting@example.com"));

  CHECK(Mailbox::validate("x@example.com"));
  CHECK(Mailbox::validate("example-indeed@strange-example.com"));

  // (local domain name with no TLD, although ICANN highly discourages
  // dotless email addresses)
  CHECK(Mailbox::validate("admin@mailserver1"));

  // (see the List of Internet top-level domains)
  CHECK(Mailbox::validate("example@s.example"));

  // (space between the quotes)
  CHECK(Mailbox::validate("\" \"@example.org"));

  // (quoted angle brackets)
  CHECK(Mailbox::validate("\"\\<foo-bar\\>\"@example.org"));

  // (quoted double dot)
  CHECK(Mailbox::validate("\"john..doe\"@example.org"));

  // (bangified host route used for uucp mailers)
  CHECK(Mailbox::validate("mailhost!username@example.org"));

  // (% escaped mail route to user@example.com via example.org)
  CHECK(Mailbox::validate("user%example.com@example.org"));

  // Invalid email addresses

  CHECK(!Mailbox::validate("Abc.example.com")); // (no @ character)

  CHECK(!Mailbox::validate("A@b@c@example.com")); // (only one @ is allowed)

  // (none of the special characters in this local-part are allowed
  // outside quotation marks)
  CHECK(!Mailbox::validate("a\"b(c)d,e:f;g<h>i[j\\k]l@example.com"));

  // (quoted strings must be dot separated or the only element making
  // up the local-part)
  CHECK(!Mailbox::validate("just\"not\"right@example.com"));

  // (spaces, quotes, and backslashes may only exist when within
  // quoted strings and preceded by a backslash)
  CHECK(!Mailbox::validate("this is\"not\\allowed@example.com"));

  // (even if escaped (preceded by a backslash), spaces, quotes, and
  // backslashes must still be contained by quotes)
  CHECK(!Mailbox::validate("this\\ still\\\"not\\\\allowed@example.com"));

  // (local part is longer than 64 characters)
  CHECK(!Mailbox::validate_strict_lengths(
      "1234567890123456789012345678901234567890123456789012345"
      "678901234+x@example.com"));

  CHECK(Mailbox::validate("gene@digilicious.com"));
  CHECK(Mailbox::validate("gene@[127.0.0.1]"));
  CHECK(!Mailbox::validate("gene@[127.999.0.1]"));
  CHECK(!Mailbox::validate("allen@bad_d0main.com"));

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

  CHECK(!Mailbox::validate("2962"));
  CHECK(Mailbox::validate("실례@실례.테스트"));

  // <https://docs.microsoft.com/en-us/archive/blogs/testing123/email-address-test-cases>

  // Valid email addresses:
  CHECK(Mailbox::validate("email@domain.com"));

  // Email contains dot in the local part, a dot-atom-string.
  CHECK(Mailbox::validate("firstname.lastname@domain.com"));

  // Multiple lables in domain.
  CHECK(Mailbox::validate("email@subdomain.domain.com"));

  // Plus sign is a valid character.
  CHECK(Mailbox::validate("firstname+lastname@domain.com"));

  // Domain is valid IP address, but this is matched as a domain.
  CHECK(Mailbox::validate("email@123.123.123.123"));

  // Square bracket around IP address is a "address literal."
  CHECK(Mailbox::validate("email@[123.123.123.123]"));

  // Quotes around local part is valid.
  CHECK(Mailbox::validate("\"email\"@domain.com"));

  // Digits in address are valid.
  CHECK(Mailbox::validate("1234567890@domain.com"));

  // Dash in domain name is valid.
  CHECK(Mailbox::validate("email@domain-one.com"));

  // Underscore in the address field is valid.
  CHECK(Mailbox::validate("_______@domain.com"));

  CHECK(Mailbox::validate("email@domain.name"));
  CHECK(Mailbox::validate("email@domain.co.jp"));

  // Dash in local part is valid.
  CHECK(Mailbox::validate("firstname-lastname@domain.com"));

  CHECK(!Mailbox::validate("plainaddress"));     // Missing @ sign and domain
  CHECK(!Mailbox::validate("#@%^%#$@#$@#.com")); // Garbage
  CHECK(!Mailbox::validate("@domain.com"));      // Missing username

  CHECK(!Mailbox::validate("Joe Smith <email@domain.com>"));

  CHECK(!Mailbox::validate("email.domain.com"));        // Missing @
  CHECK(!Mailbox::validate("email@domain@domain.com")); // Two @ sign

  // Leading dot in address is not allowed
  CHECK(!Mailbox::validate(".email@domain.com"));

  // Trailing dot in address is not allowed
  CHECK(!Mailbox::validate("email.@domain.com"));

  // Multiple dots
  CHECK(!Mailbox::validate("email..email@domain.com"));

  // OK! Unicode char as address
  CHECK(Mailbox::validate("あいうえお@domain.com"));

  // Comment not allowed in 5321 mailbox.
  CHECK(!Mailbox::validate("email@domain.com (Joe Smith)"));

  // Missing top level domain (.com/.net/.org/etc).
  CHECK(Mailbox::validate("email@domain"));

  // Leading dash in front of domain is invalid.
  CHECK(!Mailbox::validate("email@-domain.com"));

  // .web is not a valid top level domain, oh yeah? says who?
  CHECK(Mailbox::validate("email@domain.web"));

  // Invalid IP address.
  CHECK(!Mailbox::validate("email@[111.222.333.44444]"));

  // Invalid IP address, but valid domain name as it turns out.
  CHECK(Mailbox::validate("email@111.222.333.44444"));

  // Not a valid domain name.
  CHECK(!Mailbox::validate("email@domain..com"));

  // general_address_literal
  CHECK(Mailbox::validate("email@[x:~Foo_Bar_Baz<\?\?>]"));

  std::cout << "sizeof(Mailbox) == " << sizeof(Mailbox) << '\n';
}

// Email address parsing and validating.

#include <cassert>
#include <string>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

struct Address {
  std::string local_part;
  std::string domain;
};

namespace RFC3629 {
// clang-format off

// 4.  Syntax of UTF-8 Byte Sequences

struct UTF8_tail : range<'\x80', '\xBF'> {};

struct UTF8_1 : range<0x00, 0x7F> {};

struct UTF8_2 : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3 : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                    seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                    seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                    seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4 : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
                    seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
                    seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

struct non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

} // namespace RFC3629

namespace Chars {
struct VUCHAR : sor<VCHAR, RFC3629::non_ascii> {};

// excluded from atext: "(),.@[]"
struct atext : sor<ALPHA, DIGIT,
                   one<'!', '#',
                       '$', '%',
                       '&', '\'',
                       '*', '+',
                       '-', '/',
                       '=', '?',
                       '^', '_',
                       '`', '{',
                       '|', '}',
                       '~'>,
                   RFC3629::non_ascii> {};

} // namespace Chars

namespace RFC5321 {
// <https://tools.ietf.org/html/rfc5321>

using dot = one<'.'>;
using colon = one<':'>;

struct u_let_dig : sor<ALPHA, DIGIT, RFC3629::non_ascii> {};

struct u_ldh_tail : star<sor<seq<plus<one<'-'>>, u_let_dig>, u_let_dig>> {};

struct u_label : seq<u_let_dig, u_ldh_tail> {};

struct let_dig : sor<ALPHA, DIGIT> {};

struct ldh_tail : star<sor<seq<plus<one<'-'>>, let_dig>, let_dig>> {};

struct ldh_str : seq<let_dig, ldh_tail> {};

struct label : ldh_str {};

struct sub_domain : sor<label, u_label> {};

struct domain : list<sub_domain, dot> {};

struct dec_octet : sor<seq<string<'2','5'>, range<'0','5'>>,
                       seq<one<'2'>, range<'0','4'>, DIGIT>,
                       seq<range<'0', '1'>, rep<2, DIGIT>>,
                       rep_min_max<1, 2, DIGIT>> {};

struct IPv4_address_literal : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {};

struct h16 : rep_min_max<1, 4, HEXDIG> {};

struct ls32 : sor<seq<h16, colon, h16>, IPv4_address_literal> {};

struct dcolon : two<':'> {};

struct IPv6address : sor<seq<                                          rep<6, h16, colon>, ls32>,
                         seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                         seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>,
                         seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                         seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                         seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                         seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                         seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                         seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};

struct IPv6_address_literal : seq<TAO_PEGTL_ISTRING("IPv6:"), IPv6address> {};

struct dcontent : ranges<33, 90, 94, 126> {};

struct standardized_tag : ldh_str {};

struct general_address_literal : seq<standardized_tag, colon, plus<dcontent>> {};

// 4.1.3.  Address Literals
struct address_literal : seq<one<'['>,
                             sor<IPv4_address_literal,
                                 IPv6_address_literal,
                                 general_address_literal>,
                             one<']'>> {};


struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, RFC3629::non_ascii> {};
struct graphic : range<32, 126> {};
struct quoted_pairSMTP : seq<one<'\\'>, graphic> {};
struct qcontentSMTP : sor<qtextSMTP, quoted_pairSMTP> {};

struct atom : plus<Chars::atext> {};
struct dot_string : list<atom, dot> {};
struct quoted_string : seq<one<'"'>, star<qcontentSMTP>, one<'"'>> {};
struct local_part : sor<dot_string, quoted_string> {};
struct non_local_part : sor<domain, address_literal> {};
struct mailbox : seq<local_part, one<'@'>, non_local_part> {};
struct mailbox_only : seq<mailbox, eof> {};

// clang-format on
// Actions

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<local_part> {
  template <typename Input>
  static void apply(Input const& in, Address& addr)
  {
    addr.local_part = in.string();
  }
};

template <>
struct action<non_local_part> {
  template <typename Input>
  static void apply(Input const& in, Address& addr)
  {
    addr.domain = in.string();
  }
};
} // namespace RFC5321

namespace RFC5322 {
// <https://tools.ietf.org/html/rfc5322>
// clang-format off

using dot = one<'.'>;

struct quoted_pair : seq<one<'\\'>, sor<Chars::VUCHAR, WSP>> {};

// 3.2.2.  Folding White Space and Comments

struct FWS : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// ctext is ASCII but not '(' or ')' or '\\', plus non-ASCII
struct ctext : sor<ranges<33, 39, 42, 91, 93, 126>, RFC3629::non_ascii> {};

struct comment;

struct ccontent : sor<ctext, quoted_pair, comment> {};

struct comment : seq<one<'('>, star<seq<opt<FWS>, ccontent>>, opt<FWS>, one<')'>> {};

struct CFWS : sor<seq<plus<seq<opt<FWS>, comment>, opt<FWS>>>, FWS> {};

// 3.2.3.  Atom

struct atom : seq<opt<CFWS>, plus<Chars::atext>, opt<CFWS>> {};
struct dot_atom_text : list<plus<Chars::atext>, dot> {};
struct dot_atom : seq<opt<CFWS>, dot_atom_text, opt<CFWS>> {};

// 3.2.4.  Quoted Strings

struct qtext : sor<one<33>, ranges<35, 91, 93, 126>, RFC3629::non_ascii> {};
struct qcontent : sor<qtext, quoted_pair> {};

// Corrected in errata ID: 3135
struct quoted_string
  : seq<opt<CFWS>,
        DQUOTE,
        sor<seq<star<seq<opt<FWS>, qcontent>>, opt<FWS>>, FWS>,
        DQUOTE,
        opt<CFWS>> {};

// 3.2.5.  Miscellaneous Tokens

struct word : sor<atom, quoted_string> {};
struct phrase : plus<word> {};

// 3.4.1.  Addr-Spec Specification

struct dtext : ranges<33, 90, 94, 126> {};
struct domain_literal : seq<opt<CFWS>,
                            one<'['>, star<seq<opt<FWS>, dtext>>, opt<FWS>, one<']'>,
                            opt<CFWS>> {};
struct domain : sor<dot_atom, domain_literal> {};
struct local_part : sor<dot_atom, quoted_string> {};
struct addr_spec : seq<local_part, one<'@'>, domain> {};

// 3.4 Address Specification

struct group_list;
struct display_name : phrase {};
struct group : seq<display_name, one<':'>, opt<group_list>, one<';'>, opt<CFWS>> {};
struct angle_addr : seq<opt<CFWS>, one<'<'>, addr_spec, one<'>'>, opt<CFWS>> {};
struct name_addr : seq<opt<display_name>, angle_addr> {};
struct mailbox : sor<name_addr, addr_spec> {};
struct mailbox_list : list<mailbox, one<','>> {};
struct group_list : sor<mailbox_list, CFWS> {};
struct address : sor<mailbox, group> {};
struct address_only : seq<address, eof> {};

// clang-format on
// Actions

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<local_part> {
  template <typename Input>
  static void apply(Input const& in, Address& addr)
  {
    addr.local_part = in.string();
  }
};

template <>
struct action<domain> {
  template <typename Input>
  static void apply(Input const& in, Address& addr)
  {
    addr.domain = in.string();
  }
};
} // namespace RFC5322

bool validate_mailbox(std::string_view value)
{
  Address addr;

  memory_input<> address_in(value, "address");
  if (!parse<RFC5321::mailbox_only, RFC5321::action>(address_in, addr)) {
    return false;
  }

  // RFC-5321 section 4.5.3.1.  Size Limits and Minimums

  if (addr.local_part.length() > 64) { // Section 4.5.3.1.1.  Local-part
    return false;
  }
  if (addr.domain.length() > 255) { // Section 4.5.3.1.2.
    // Also RFC 2181 section 11. Name syntax
    return false;
  }

  // FIXME
  // each label is limited to between 1 and 63 octets

  return true;
}

bool validate_address(std::string_view value)
{
  Address addr;

  memory_input<> address_in(value, "address");
  if (!parse<RFC5322::address_only, RFC5322::action>(address_in, addr)) {
    return false;
  }

  return true;
}

int main()
{
  // <https://en.wikipedia.org/wiki/Email_address#Examples>

  // Valid email addresses

  assert(validate_mailbox("simple@example.com"));
  assert(validate_mailbox("very.common@example.com"));
  assert(validate_mailbox("disposable.style.email.with+symbol@example.com"));
  assert(validate_mailbox("other.email-with-hyphen@example.com"));
  assert(validate_mailbox("fully-qualified-domain@example.com"));

  // (may go to user.name@example.com inbox depending on mail server)
  assert(validate_mailbox("user.name+tag+sorting@example.com"));

  assert(validate_mailbox("x@example.com"));
  assert(validate_mailbox("example-indeed@strange-example.com"));

  // (local domain name with no TLD, although ICANN highly discourages
  // dotless email addresses)
  assert(validate_mailbox("admin@mailserver1"));

  // (see the List of Internet top-level domains)
  assert(validate_mailbox("example@s.example"));

  // (space between the quotes)
  assert(validate_mailbox("\" \"@example.org"));

  // (quoted double dot)
  assert(validate_mailbox("\"john..doe\"@example.org"));

  // (bangified host route used for uucp mailers)
  assert(validate_mailbox("mailhost!username@example.org"));

  // (% escaped mail route to user@example.com via example.org)
  assert(validate_mailbox("user%example.com@example.org"));

  // Invalid email addresses

  assert(!validate_mailbox("Abc.example.com")); // (no @ character)

  assert(!validate_mailbox("A@b@c@example.com")); // (only one @ is allowed)

  // (none of the special characters in this local-part are allowed
  // outside quotation marks)
  assert(!validate_mailbox("a\"b(c)d,e:f;g<h>i[j\\k]l@example.com"));

  // (quoted strings must be dot separated or the only element making
  // up the local-part)
  assert(!validate_mailbox("just\"not\"right@example.com"));

  // (spaces, quotes, and backslashes may only exist when within
  // quoted strings and preceded by a backslash)
  assert(!validate_mailbox("this is\"not\\allowed@example.com"));

  // (even if escaped (preceded by a backslash), spaces, quotes, and
  // backslashes must still be contained by quotes)
  assert(!validate_mailbox("this\\ still\\\"not\\\\allowed@example.com"));

  // (local part is longer than 64 characters)
  assert(!validate_mailbox(
      "1234567890123456789012345678901234567890123456789012345"
      "678901234+x@example.com"));

  assert(!validate_address("foo bar@digilicious.com"));
  assert(validate_address("gene@digilicious.com"));
  assert(validate_address("Gene Hightower <gene@digilicious.com>"));
  assert(validate_address("gene@[127.999.0.1]"));
  assert(validate_address("madness!@example.org"));
  assert(validate_address("(comment)mailbox@example.com"));

  assert(validate_mailbox("gene@digilicious.com"));
  assert(validate_mailbox("gene@[127.0.0.1]"));
  assert(!validate_mailbox("gene@[127.999.0.1]"));
  assert(!validate_mailbox("allen@bad_d0main.com"));

  assert(!validate_mailbox("2962"));
  assert(validate_mailbox("실례@실례.테스트"));

  // <https://docs.microsoft.com/en-us/archive/blogs/testing123/email-address-test-cases>

  // Valid email addresses:
  assert(validate_mailbox("email@domain.com"));

  // Email contains dot in the local part, a dot-atom-string.
  assert(validate_mailbox("firstname.lastname@domain.com"));

  // Multiple lables in domain.
  assert(validate_mailbox("email@subdomain.domain.com"));

  // Plus sign is a valid character.
  assert(validate_mailbox("firstname+lastname@domain.com"));

  // Domain is valid IP address, but this is matched as a domain.
  assert(validate_mailbox("email@123.123.123.123"));

  // Square bracket around IP address is a "address literal."
  assert(validate_mailbox("email@[123.123.123.123]"));

  // Quotes around local part is valid.
  assert(validate_mailbox("\"email\"@domain.com"));

  // Digits in address are valid.
  assert(validate_mailbox("1234567890@domain.com"));

  // Dash in domain name is valid.
  assert(validate_mailbox("email@domain-one.com"));

  // Underscore in the address field is valid.
  assert(validate_mailbox("_______@domain.com"));

  assert(validate_mailbox("email@domain.name"));
  assert(validate_mailbox("email@domain.co.jp"));

  // Dash in local part is valid.
  assert(validate_mailbox("firstname-lastname@domain.com"));

  assert(!validate_mailbox("plainaddress"));     // Missing @ sign and domain
  assert(!validate_mailbox("#@%^%#$@#$@#.com")); // Garbage
  assert(!validate_mailbox("@domain.com"));      // Missing username

  assert(!validate_mailbox("Joe Smith <email@domain.com>"));
  assert(validate_address("Joe Smith <email@domain.com>"));

  assert(!validate_mailbox("email.domain.com"));        // Missing @
  assert(!validate_mailbox("email@domain@domain.com")); // Two @ sign

  // Leading dot in address is not allowed
  assert(!validate_mailbox(".email@domain.com"));

  // Trailing dot in address is not allowed
  assert(!validate_mailbox("email.@domain.com"));

  // Multiple dots
  assert(!validate_mailbox("email..email@domain.com"));

  // OK! Unicode char as address
  assert(validate_mailbox("あいうえお@domain.com"));

  // Comment not allowed in 5321 mailbox.
  assert(!validate_mailbox("email@domain.com (Joe Smith)"));

  // Comment fine in 5322 address.
  assert(validate_address("email@domain.com (Joe Smith)"));

  // Missing top level domain (.com/.net/.org/etc).
  assert(validate_mailbox("email@domain"));

  // Leading dash in front of domain is invalid.
  assert(!validate_mailbox("email@-domain.com"));

  // .web is not a valid top level domain, oh yeah? says who?
  assert(validate_mailbox("email@domain.web"));

  // Invalid IP address.
  assert(!validate_mailbox("email@[111.222.333.44444]"));

  // Invalid IP address, but valid domain name as it turns out.
  assert(validate_mailbox("email@111.222.333.44444"));

  // Not a valid domain name.
  assert(!validate_mailbox("email@domain..com"));

  // general_address_literal
  assert(validate_mailbox("email@[x:~Foo_Bar_Baz<\?\?>]"));
}

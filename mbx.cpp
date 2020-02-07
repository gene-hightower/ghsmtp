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

namespace UTF8 {
// clang-format off

struct tail : range<'\x80', '\xBF'> {};

// Single unit code point, aka ASCII.
struct one_unit : range<0x00, 0x7F> {};

struct two_unit : seq<range<'\xC2', '\xDF'>, tail> {};

struct three_unit : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, tail>,
                    seq<range<'\xE1', '\xEC'>, rep<2, tail>>,
                    seq<one<'\xED'>, range<'\x80', '\x9F'>, tail>,
                    seq<range<'\xEE', '\xEF'>, rep<2, tail>>> {};

struct four_unit
  : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, tail>>,
        seq<range<'\xF1', '\xF3'>, rep<3, tail>>,
        seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, tail>>> {};

struct non_ascii : sor<two_unit, three_unit, four_unit> {};

struct VUCHAR : sor<VCHAR, non_ascii> {};

// clang-format on
} // namespace UTF8

namespace RFC5321 {
// <https://tools.ietf.org/html/rfc5321>
// clang-format off

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, UTF8::non_ascii> {};

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


struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, UTF8::non_ascii> {};
struct graphic : range<32, 126> {};
struct quoted_pairSMTP : seq<one<'\\'>, graphic> {};
struct qcontentSMTP : sor<qtextSMTP, quoted_pairSMTP> {};

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
                   UTF8::non_ascii> {};
struct atom : plus<atext> {};
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

struct quoted_pair : seq<one<'\\'>, sor<UTF8::VUCHAR, WSP>> {};

// 3.2.2.  Folding White Space and Comments

struct FWS : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// ctext is ASCII not '(' or ')' or '\\'
struct ctext : sor<ranges<33, 39, 42, 91, 93, 126>, UTF8::non_ascii> {};

struct comment;

struct ccontent : sor<ctext, quoted_pair, comment> {};

struct comment : seq<one<'('>, star<seq<opt<FWS>, ccontent>>, opt<FWS>, one<')'>> {};

struct CFWS : sor<seq<plus<seq<opt<FWS>, comment>, opt<FWS>>>, FWS> {};

// 3.2.3.  Atom

struct atext : sor<ALPHA, DIGIT,
                   one<'!'>, one<'#'>,
                   one<'$'>, one<'%'>,
                   one<'&'>, one<'\''>,
                   one<'*'>, one<'+'>,
                   one<'-'>, one<'/'>,
                   one<'='>, one<'?'>,
                   one<'^'>, one<'_'>,
                   one<'`'>, one<'{'>,
                   one<'|'>, one<'}'>,
                   one<'~'>,
                   UTF8::non_ascii> {
};

struct atom : seq<opt<CFWS>, plus<atext>, opt<CFWS>> {};

struct dot_atom_text : list<plus<atext>, dot> {};

struct dot_atom : seq<opt<CFWS>, dot_atom_text, opt<CFWS>> {};

// 3.2.4.  Quoted Strings

struct qtext : sor<one<33>, ranges<35, 91, 93, 126>, UTF8::non_ascii> {};

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

struct group
  : seq<display_name, one<':'>, opt<group_list>, one<';'>, opt<CFWS>> {};

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

bool parse_mailbox(char const* value)
{
  Address addr;

  memory_input<> address_in(value, "address");
  if (!parse<RFC5321::mailbox_only, RFC5321::action>(address_in, addr)) {
    return false;
  }

  return true;
}

bool parse_address(char const* value)
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

  assert(parse_mailbox("simple@example.com"));
  assert(parse_mailbox("very.common@example.com"));
  assert(parse_mailbox("disposable.style.email.with+symbol@example.com"));
  assert(parse_mailbox("other.email-with-hyphen@example.com"));
  assert(parse_mailbox("fully-qualified-domain@example.com"));

  assert(parse_mailbox(
      "user.name+tag+sorting@example.com")); // (may go to user.name@example.com
                                             // inbox depending on mail server)

  assert(parse_mailbox("x@example.com")); // (one-letter local-part)
  assert(parse_mailbox("example-indeed@strange-example.com"));

  assert(parse_mailbox(
      "admin@mailserver1")); // (local domain name with no TLD, although ICANN
                             // highly discourages dotless email addresses)

  assert(parse_mailbox("example@s.example")); // (see the List of Internet
                                              // top-level domains)

  assert(parse_mailbox("\" \"@example.org")); // (space between the quotes)

  assert(parse_mailbox("\"john..doe\"@example.org")); // (quoted double dot)

  assert(parse_mailbox("mailhost!username@example.org")); // (bangified host
                                                          // route used for uucp
                                                          // mailers)
  assert(parse_mailbox(
      "user%example.com@example.org")); // (% escaped mail route to
                                        // user@example.com via example.org)

  // Invalid email addresses

  assert(!parse_mailbox("Abc.example.com"));   // (no @ character)
  assert(!parse_mailbox("A@b@c@example.com")); // (only one @ is allowed outside
                                               // quotation marks)
  assert(!parse_mailbox(
      "a\"b(c)d,e:f;g<h>i[j\\k]l@example.com")); // (none of the special
                                                 // characters in this
                                                 // local-part are allowed
                                                 // outside quotation marks)

  assert(!parse_mailbox(
      "just\"not\"right@example.com")); // (quoted strings must be dot separated
                                        // or the only element making up the
                                        // local-part)
  assert(!parse_mailbox(
      "this is\"not\\allowed@example.com")); // (spaces, quotes, and backslashes
                                             // may only exist when within
                                             // quoted strings and preceded by a
                                             // backslash)

  assert(!parse_mailbox(
      "this\\ still\\\"not\\\\allowed@example.com")); // (even if escaped
                                                      // (preceded by a
                                                      // backslash), spaces,
                                                      // quotes, and backslashes
                                                      // must still be contained
                                                      // by quotes)

  // FIXME!!!
  assert(parse_mailbox("1234567890123456789012345678901234567890123456789012345"
                       "678901234+x@example.com")); // (local part is longer
                                                    // than 64 characters)

  assert(!parse_address("foo bar@digilicious.com"));
  assert(parse_address("gene@digilicious.com"));
  assert(parse_address("Gene Hightower <gene@digilicious.com>"));
  assert(parse_address("gene@[127.999.0.1]"));
  assert(parse_address("madness!@example.org"));
  assert(parse_address("(comment)mailbox@example.com"));

  assert(parse_mailbox("gene@digilicious.com"));
  assert(parse_mailbox("gene@[127.0.0.1]"));
  assert(!parse_mailbox("gene@[127.999.0.1]"));
  assert(!parse_mailbox("allen@bad_d0main.com"));

  assert(!parse_mailbox("2962"));
  assert(parse_mailbox("실례@실례.테스트"));

  // <https://docs.microsoft.com/en-us/archive/blogs/testing123/email-address-test-cases>

  assert(parse_mailbox("email@domain.com"));              // Valid email
  assert(parse_mailbox("firstname.lastname@domain.com")); // Email contains
                                                          // dot in the address
                                                          // field
  assert(parse_mailbox("email@subdomain.domain.com"));    // Email contains
                                                          // dot with subdomain
  assert(parse_mailbox("firstname+lastname@domain.com")); // Plus sign is
                                                          // considered valid
                                                          // character
  assert(parse_mailbox("email@123.123.123.123"));         // Domain is valid IP
                                                          // address
  assert(parse_mailbox("email@[123.123.123.123]")); // Square bracket around IP
                                                    // address is considered
                                                    // valid
  assert(parse_mailbox("\"email\"@domain.com"));    // Quotes around email is
                                                    // considered valid
  assert(parse_mailbox("1234567890@domain.com"));   // Digits in address are
                                                    // valid
  assert(parse_mailbox("email@domain-one.com"));    // Dash in domain name is
                                                    // valid
  assert(parse_mailbox("_______@domain.com"));      // Underscore in the
                                                    // address field is valid
  assert(parse_mailbox("email@domain.name"));       // .name is valid Top Level
                                                    // Domain name
  assert(parse_mailbox("email@domain.co.jp"));      // Dot in Top Level Domain
                                               // name also considered valid
                                               // (use co.jp as example here)

  assert(parse_mailbox("firstname-lastname@domain.com")); // Dash in address
                                                          // field is valid

  assert(!parse_mailbox("plainaddress"));     // Missing @ sign and domain
  assert(!parse_mailbox("#@%^%#$@#$@#.com")); // Garbage
  assert(!parse_mailbox("@domain.com"));      // Missing username

  assert(!parse_mailbox("Joe Smith <email@domain.com>")); // Encoded html within
                                                          // email is invalid

  assert(parse_address("Joe Smith <email@domain.com>")); // Ok by RFC-5322

  assert(!parse_mailbox("email.domain.com"));        // Missing @
  assert(!parse_mailbox("email@domain@domain.com")); // Two @ sign

  assert(!parse_mailbox(".email@domain.com")); // Leading dot in address
                                               // is not allowed

  assert(!parse_mailbox("email.@domain.com")); // Trailing dot in address
                                               // is not allowed

  assert(!parse_mailbox("email..email@domain.com")); // Multiple dots

  assert(parse_mailbox("あいうえお@domain.com")); // OK!! Unicode char as
                                                  // address

  assert(!parse_mailbox("email@domain.com (Joe Smith)")); // Text followed
                                                          // email is not
                                                          // allowed

  assert(parse_address("email@domain.com (Joe Smith)")); // Text followed
                                                         // email is ok by 5322

  assert(parse_mailbox("email@domain")); // Missing top level domain
                                         // (.com/.net/.org/etc)

  assert(!parse_mailbox("email@-domain.com")); // Leading dash in front of
                                               // domain is invalid

  assert(parse_mailbox("email@domain.web")); // .web is not a valid top
                                             // level domain

  assert(!parse_mailbox("email@[111.222.333.44444]")); // Invalid IP
                                                       // format

  assert(parse_mailbox("email@111.222.333.44444")); // Invalid IP
                                                    // format, but valid domain
                                                    // name

  assert(!parse_mailbox("email@domain..com"));
}

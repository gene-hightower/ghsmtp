#include "Mailbox.hpp"

#include <string>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

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
  static void apply(Input const& in, Mailbox& addr)
  {
    addr.set_local(in.string());
  }
};

template <>
struct action<non_local_part> {
  template <typename Input>
  static void apply(Input const& in, Mailbox& addr)
  {
    addr.set_domain(in.string());
  }
};
} // namespace RFC5321

bool Mailbox::validate(std::string_view mailbox)
{
  Mailbox        mbx;
  memory_input<> address_in(mailbox, "address");
  return !mailbox.empty()
         && parse<RFC5321::mailbox_only, RFC5321::action>(address_in, mbx)
         && (mbx.local_part().length() <= 64)
         && (mbx.domain().ascii().length() <= 255);
}

Mailbox::Mailbox(std::string_view mailbox)
{
  if (!mailbox.empty()) {
    memory_input<> address_in(mailbox, "address");
    if (!parse<RFC5321::mailbox_only, RFC5321::action>(address_in, *this)) {
      throw std::invalid_argument("invalid mailbox syntax");
    }
  }

  // RFC-5321 section 4.5.3.1.  Size Limits and Minimums

  if (local_part().length() > 64) { // Section 4.5.3.1.1.  Local-part
    throw std::invalid_argument("local part > 64 octets");
  }
  if (domain().ascii().length() > 255) { // Section 4.5.3.1.2.
    // Also RFC 2181 section 11. Name syntax
    throw std::invalid_argument("domain > 255 octets");
  }

  // FIXME
  // Check that each label is limited to between 1 and 63 octets.
}

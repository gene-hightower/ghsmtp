#include "Session.hpp"

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

// #include <tao/pegtl/tracer.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;
using namespace tao::pegtl::alphabet;

namespace smtp {

struct no_last_dash {
  template <tao::pegtl::apply_mode A,
            tao::pegtl::rewind_mode M,
            template <typename...> class Action,
            template <typename...> class Control,
            typename Input>
  static bool match(Input& in)
  {
    if (in.string().back() != '-') {
      in.bump(in.string().size());
      return true;
    }
    return false;
  }
};

struct UTF8_tail : range<0x80, 0xBF> {
};

struct UTF8_1 : range<0x00, 0x7F> {
};

struct UTF8_2 : seq<range<0xC2, 0xDF>, UTF8_tail> {
};

struct UTF8_3 : sor<seq<one<0xE0>, range<0xA0, 0xBF>, UTF8_tail>,
                    seq<range<0xE1, 0xEC>, rep<2, UTF8_tail>>,
                    seq<one<0xED>, range<0x80, 0x9F>, UTF8_tail>,
                    seq<range<0xEE, 0xEF>, rep<2, UTF8_tail>>> {
};

struct UTF8_4 : sor<seq<one<0xF0>, range<0x90, 0xBF>, rep<2, UTF8_tail>>,
                    seq<range<0xF1, 0xF3>, rep<3, UTF8_tail>>,
                    seq<one<0xF4>, range<0x80, 0x8F>, rep<2, UTF8_tail>>> {
};

// UTF8_char = UTF8_1 | UTF8_2 | UTF8_3 | UTF8_4;

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {
};

struct U_let_dig : sor<ALPHA, DIGIT, UTF8_non_ascii> {
};

struct U_ldh_str : plus<sor<ALPHA, DIGIT, UTF8_non_ascii, one<'-'>>> {
  // verify last char is a U_Let_dig
};

struct U_label : seq<U_let_dig, opt<U_ldh_str>> {
};

struct Let_dig : sor<ALPHA, DIGIT> {
};

struct Ldh_str : plus<sor<ALPHA, DIGIT, one<'-'>>> {
  // verify last char is a U_Let_dig
};

struct label : seq<Let_dig, opt<Ldh_str>> {
};

struct sub_domain : sor<label, U_label> {
};

struct Domain : list<sub_domain, one<'.'>> {
};

using dot = one<'.'>;
using colon = one<':'>;

// clang-format off
struct dec_octet : sor<one<'0'>,
                       rep_min_max<1, 2, DIGIT>,
                       seq<one<'1'>, DIGIT, DIGIT>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<string<'2','5'>, range<'0','5'>>> {};
// clang-format on

struct IPv4_address_literal
    : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {
};

struct h16 : rep_min_max<1, 4, HEXDIG> {
};

struct ls32 : sor<seq<h16, colon, h16>, IPv4_address_literal> {
};

struct dcolon : two<':'> {
};

// clang-format off
struct IPv6address : sor<seq<                                          rep<6, h16, colon>, ls32>,
                         seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                         seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>, 
                         seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                         seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                         seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                         seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                         seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                         seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};
// clang-format on

struct IPv6_address_literal : seq<TAOCPP_PEGTL_STRING("IPv6:"), IPv6address> {
};

struct dcontent : ranges<33, 90, 94, 126> {
};

struct standardized_tag : Ldh_str {
};

struct General_address_literal : seq<standardized_tag, colon, plus<dcontent>> {
};

// See rfc 5321 Section 4.1.3
struct address_literal : seq<one<'['>,
                             sor<IPv4_address_literal,
                                 IPv6_address_literal,
                                 General_address_literal>,
                             one<']'>> {
};

struct At_domain : seq<one<'@'>, Domain> {
};

struct A_d_l : list<At_domain, one<','>> {
};

struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, UTF8_non_ascii> {
};

struct print : range<32, 126> {
};

struct quoted_pairSMTP : sor<one<'\\'>, print> {
};

struct QcontentSMTP : sor<qtextSMTP, quoted_pairSMTP> {
};

struct Quoted_string : seq<one<'"'>, star<QcontentSMTP>, one<'"'>> {
};

// clang-format off
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
                   UTF8_non_ascii> {
};
// clang-format on

struct Atom : plus<atext> {
};

struct Dot_string : list<Atom, one<'.'>> {
};

struct Local_part : sor<Dot_string, Quoted_string> {
};

struct Mailbox : seq<Local_part, one<'@'>, sor<Domain, address_literal>> {
};

struct Path : seq<one<'<'>, seq<opt<seq<A_d_l, colon>, Mailbox>, one<'>'>>> {
};

struct Reverse_path : sor<Path, TAOCPP_PEGTL_STRING("<>")> {
};

struct esmtp_keyword
    : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, one<'-'>>>> {
};

struct esmtp_value : plus<sor<range<33, 60>, range<62, 126>, UTF8_non_ascii>> {
};

struct esmtp_param : seq<esmtp_keyword, opt<seq<one<'='>, esmtp_value>>> {
};

struct Mail_parameters : list<esmtp_param, SP> {
};

struct helo : seq<TAOCPP_PEGTL_ISTRING("HELO "), Domain, CRLF> {
};

struct ehlo : seq<TAOCPP_PEGTL_ISTRING("EHLO "), Domain, CRLF> {
};

struct mail_from : seq<TAOCPP_PEGTL_ISTRING("MAIL FROM:"),
                       Reverse_path,
                       opt<seq<SP, Mail_parameters>>,
                       CRLF> {
};

struct quit : seq<TAOCPP_PEGTL_ISTRING("QUIT"), CRLF> {
};

struct any_cmd : sor<helo, ehlo, mail_from, quit> {
};

struct cmds : star<any_cmd> {
};

struct grammar : seq<cmds, eof> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<helo> {
  template <typename Input>
  static void apply(const Input& in, Session& session)
  {
    auto ln = in.string();
    // 5 is the length of "HELO " and two more for the CRLF.
    auto dom = ln.substr(5, ln.length() - 7);
    session.helo(dom);
  }
};

template <>
struct action<ehlo> {
  template <typename Input>
  static void apply(const Input& in, Session& session)
  {
    auto ln = in.string();
    // 5 is the length of "EHLO " and two more for the CRLF.
    auto dom = ln.substr(5, ln.length() - 7);
    session.ehlo(dom);
  }
};

template <>
struct action<quit> {
  template <typename Input>
  static void apply(const Input& in, Session& session)
  {
    LOG(INFO) << "quit";
    session.quit();
  }
};

// template<>
// struct u_no_last_dash<U_Ldh_str> {
//   template <typename Input>
//   static void apply(const Input& in, Session& session)
//   {
//   }
// };

// template<>
// struct no_last_dash<Ldh_str> {
//   template <typename Input>
//   static void apply(const Input& in, Session& session)
//   {
//   }
// };
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  // Don't wait for STARTTLS to fail if no cert.
  CHECK(boost::filesystem::exists(TLS::cert_path)) << "can't find cert file";

  Session session;
  session.greeting();

  session.in().unsetf(std::ios::skipws);

  istream_input<crlf_eol> in(session.in(), 1024, "session");

  try {
    LOG(INFO) << "calling parse";
    parse<smtp::grammar, smtp::action>(in, session);
    LOG(INFO) << "parse return";
  }
  catch (parse_error const& e) {
    std::cout << e.what() << '\n';
    return 1;
  }
}

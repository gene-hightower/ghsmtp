#include "Session.hpp"

#include <cstdlib>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;
using namespace tao::pegtl::alphabet;

namespace smtp {

struct Ctx {
  Session session;

  Message msg;
  size_t msg_bytes{0};

  std::string mb_loc;
  std::string mb_dom;

  std::pair<std::string, std::string> param;
  std::unordered_map<std::string, std::string> parameters;

  size_t chunk_size;
  bool chunk_first{true};
  bool chunk_last{false};
  bool bdat_error{false};

  void bdat_rset()
  {
    chunk_first = true;
    chunk_last = false;
    bdat_error = false;
  }
};

struct no_last_dash {
  // Something like this to fix up U_ldh_str and Ldh_str rules.
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

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {
};

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct U_let_dig : sor<ALPHA, DIGIT, UTF8_non_ascii> {
};

struct U_ldh_str : plus<sor<ALPHA, DIGIT, UTF8_non_ascii, dash>> {
  // verify last char is a U_Let_dig
};

struct U_label : seq<U_let_dig, opt<U_ldh_str>> {
};

struct Let_dig : sor<ALPHA, DIGIT> {
};

struct Ldh_str : plus<sor<ALPHA, DIGIT, dash>> {
  // verify last char is a U_Let_dig
};

struct label : seq<Let_dig, opt<Ldh_str>> {
};

struct sub_domain : sor<label, U_label> {
};

struct Domain : list<sub_domain, dot> {
};

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

struct graphic : range<32, 126> {
};

struct quoted_pairSMTP : seq<one<'\\'>, graphic> {
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

struct Dot_string : list<Atom, dot> {
};

struct Local_part : sor<Dot_string, Quoted_string> {
};

struct Non_local_part : sor<Domain, address_literal> {
};

struct Mailbox : seq<Local_part, one<'@'>, Non_local_part> {
};

struct Path : seq<one<'<'>, seq<opt<seq<A_d_l, colon>>, Mailbox, one<'>'>>> {
};

struct bounce_path : TAOCPP_PEGTL_STRING("<>") {
};

struct Reverse_path : sor<Path, bounce_path> {
};

struct magic_postmaster : TAOCPP_PEGTL_STRING("<Postmaster>") {
};

struct Forward_path : sor<Path, magic_postmaster> {
};

struct esmtp_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash>>> {
};

struct esmtp_value : plus<sor<range<33, 60>, range<62, 126>, UTF8_non_ascii>> {
};

struct esmtp_param : seq<esmtp_keyword, opt<seq<one<'='>, esmtp_value>>> {
};

struct Mail_parameters : list<esmtp_param, SP> {
};

struct Rcpt_parameters : list<esmtp_param, SP> {
};

struct String : sor<Quoted_string, Atom> {
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

struct rcpt_to : seq<TAOCPP_PEGTL_ISTRING("RCPT TO:"),
                     Forward_path,
                     opt<seq<SP, Rcpt_parameters>>,
                     CRLF> {
};

struct chunk_size : plus<DIGIT> {
};

struct end_marker : TAOCPP_PEGTL_ISTRING(" LAST") {
};

struct bdat
    : seq<TAOCPP_PEGTL_ISTRING("BDAT "), chunk_size, opt<end_marker>, CRLF> {
};

struct data : seq<TAOCPP_PEGTL_ISTRING("DATA"), CRLF> {
};

struct data_end : seq<dot, CRLF> {
};

struct data_blank : CRLF {
};

struct data_dot : seq<one<'.'>, plus<not_one<'\r', '\n'>>, CRLF> {
};

struct data_plain : seq<not_one<'.'>, star<not_one<'\r', '\n'>>, CRLF> {
};

struct data_line : sor<data_blank, data_dot, data_plain> {
};

struct data_grammar : seq<star<seq<data_line, discard>>, data_end> {
};

struct rset : seq<TAOCPP_PEGTL_ISTRING("RSET"), CRLF> {
};

struct noop : seq<TAOCPP_PEGTL_ISTRING("NOOP"), opt<seq<SP, String>>, CRLF> {
};

struct vrfy : seq<TAOCPP_PEGTL_ISTRING("VRFY"), opt<seq<SP, String>>, CRLF> {
};

struct help : seq<TAOCPP_PEGTL_ISTRING("HELP"), opt<seq<SP, String>>, CRLF> {
};

struct starttls : seq<TAOCPP_PEGTL_ISTRING("STARTTLS"), CRLF> {
};

struct quit : seq<TAOCPP_PEGTL_ISTRING("QUIT"), CRLF> {
};

// commands in size order

struct any_cmd : seq<sor<data,
                         quit,
                         rset,
                         noop,
                         vrfy,
                         help,
                         helo,
                         ehlo,
                         bdat,
                         starttls,
                         rcpt_to,
                         mail_from>,
                     discard> {
};

struct grammar : plus<any_cmd> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <typename Rule>
struct data_action : nothing<Rule> {
};

template <>
struct action<esmtp_keyword> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.param.first = in.string();
  }
};

template <>
struct action<esmtp_value> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.param.second = in.string();
  }
};

template <>
struct action<esmtp_param> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.parameters.insert(ctx.param);
    ctx.param.first.clear();
    ctx.param.second.clear();
  }
};

template <>
struct action<Local_part> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.mb_loc = in.string();
  }
};

template <>
struct action<Non_local_part> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.mb_dom = in.string();
  }
};

template <>
struct action<magic_postmaster> {
  static void apply0(Ctx& ctx)
  {
    ctx.mb_loc = std::string("Postmaster");
    ctx.mb_dom.clear();
  }
};

template <>
struct action<helo> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    auto ln = in.string();
    // 5 is the length of "HELO ", plus 2 for the CRLF
    auto dom = ln.substr(5, ln.length() - 7);
    ctx.session.helo(dom);
    ctx.bdat_rset();
  }
};

template <>
struct action<ehlo> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    auto ln = in.string();
    // 5 is the length of "EHLO ", plus 2 for the CRLF
    auto dom = ln.substr(5, ln.length() - 7);
    ctx.session.ehlo(dom);
    ctx.bdat_rset();
  }
};

template <>
struct action<mail_from> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.mail_from(::Mailbox(ctx.mb_loc, ctx.mb_dom), ctx.parameters);

    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
    ctx.parameters.clear();
  }
};

template <>
struct action<rcpt_to> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.rcpt_to(::Mailbox(ctx.mb_loc, ctx.mb_dom), ctx.parameters);

    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
    ctx.parameters.clear();
  }
};

template <>
struct action<chunk_size> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.chunk_size = std::strtoul(in.string().c_str(), nullptr, 10);
  }
};

template <>
struct action<end_marker> {
  static void apply0(Ctx& ctx) { ctx.chunk_last = true; }
};

template <>
struct action<bdat> {
  static void apply0(Ctx& ctx)
  {
    if (ctx.chunk_first) {
      if (!ctx.session.bdat_start()) {
        ctx.bdat_error = true;
      }
      else {
        ctx.session.data_msg(ctx.msg);
      }
      ctx.msg_bytes = 0;
      ctx.chunk_first = false;
    }
    if (ctx.chunk_size) {

      if ((ctx.msg_bytes + ctx.chunk_size) > Config::size) {
        ctx.session.data_size_error();
        ctx.bdat_error = true;

        LOG(WARNING) << "message size " << ctx.msg_bytes
                     << " exceeds maximium of " << Config::size;
      }

      std::vector<char> bfr;
      bfr.reserve(ctx.chunk_size);

      ctx.session.in().read(bfr.data(), ctx.chunk_size);

      if (!ctx.bdat_error) {
        ctx.msg.out().write(bfr.data(), ctx.chunk_size);
        ctx.msg_bytes += ctx.chunk_size;
      }
    }

    if (ctx.bdat_error) {
      ctx.session.data_error();
    }
    else {
      if (ctx.chunk_last) {
        ctx.session.data_msg_done(ctx.msg, ctx.msg_bytes);
      }
      else {
        ctx.session.bdat_msg(ctx.msg, ctx.msg_bytes);
      }
    }
  }
};

template <>
struct data_action<data_end> {
  static void apply0(Ctx& ctx)
  {
    if (ctx.msg_bytes > Config::size) {
      LOG(WARNING) << "message size " << ctx.msg_bytes
                   << " exceeds maximium of " << Config::size;
      ctx.session.data_size_error();
      ctx.msg.trash();
    }
    else {
      ctx.session.data_msg_done(ctx.msg, ctx.msg_bytes);
    }
  }
};

template <>
struct data_action<data_blank> {
  static void apply0(Ctx& ctx)
  {
    ctx.msg_bytes += 2;
    if (ctx.msg_bytes <= Config::size) {
      ctx.msg.out() << "\r\n";
    }
  }
};

template <>
struct data_action<data_plain> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    auto len = in.string().length();
    ctx.msg_bytes += len;
    if (ctx.msg_bytes <= Config::size) {
      ctx.msg.out().write(in.string().data(), len);
    }
  }
};

template <>
struct data_action<data_dot> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    auto len = in.string().length() - 1;
    ctx.msg_bytes += len;
    if (ctx.msg_bytes <= Config::size) {
      ctx.msg.out().write(in.string().data() + 1, len);
    }
  }
};

template <>
struct action<data> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    if (ctx.session.data_start()) {
      ctx.session.data_msg(ctx.msg);
      ctx.msg_bytes = 0;

      istream_input<eol::crlf> data_in(ctx.session.in(), 4 * 1024, "data");

      parse_nested<smtp::data_grammar, smtp::data_action>(in, data_in, ctx);
    }
  }
};

template <>
struct action<rset> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.rset();
    ctx.bdat_rset();
  }
};

template <>
struct action<noop> {
  static void apply0(Ctx& ctx) { ctx.session.noop(); }
};

template <>
struct action<vrfy> {
  static void apply0(Ctx& ctx) { ctx.session.vrfy(); }
};

template <>
struct action<help> {
  static void apply0(Ctx& ctx) { ctx.session.help(); }
};

template <>
struct action<starttls> {
  static void apply0(Ctx& ctx) { ctx.session.starttls(); }
};

template <>
struct action<quit> {
  static void apply0(Ctx& ctx) { ctx.session.quit(); }
};
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  // Don't wait for STARTTLS to fail if no cert.
  CHECK(boost::filesystem::exists(TLS::cert_path)) << "can't find cert file";

  smtp::Ctx ctx;

  ctx.session.greeting();

  ctx.session.in().unsetf(std::ios::skipws);

  istream_input<eol::crlf> in(ctx.session.in(), 4 * 1024, "session");

  try {
    if (!parse<smtp::grammar, smtp::action>(in, ctx)) {
      if (ctx.session.timed_out()) {
        ctx.session.time_out();
      }
      else {
        ctx.session.error("syntax error from parser");
      }
      return 1;
    }
  }
  catch (parse_error const& e) {
    ctx.session.error(e.what());
    return 1;
  }
  ctx.session.error("unknown parser problem");
}

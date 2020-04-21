#include <gflags/gflags.h>
namespace gflags {
}

// This needs to be at least the length of each string it's trying to match.
DEFINE_uint64(bfr_size, 4 * 1024, "parser buffer size");

DEFINE_uint64(max_xfer_size, 64 * 1024, "maximum BDAT transfer size");

#include <fstream>

#include "Session.hpp"
#include "esc.hpp"
#include "fs.hpp"
#include "iobuffer.hpp"
#include "osutil.hpp"

#include <cstdlib>
#include <memory>

#include <signal.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace RFC5321 {

struct Ctx {
  Session session;

  std::string mb_loc;
  std::string mb_dom;

  std::pair<std::string, std::string>          param;
  std::unordered_map<std::string, std::string> parameters;

  std::streamsize chunk_size;

  Ctx(fs::path config_path, std::function<void(void)> read_hook)
    : session(config_path, read_hook)
  {
  }
};

// clang-format off

struct UTF8_tail : range<'\x80', '\xBF'> {};

struct UTF8_1 : range<'\x00', '\x7F'> {};

struct UTF8_2 : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3 : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                    seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                    seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                    seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4 : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
                    seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
                    seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {};

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, UTF8_non_ascii> {};

struct u_ldh_tail : star<sor<seq<plus<one<'-'>>, u_let_dig>, u_let_dig>> {};

struct u_label : seq<u_let_dig, u_ldh_tail> {};

struct let_dig : sor<ALPHA, DIGIT> {};

struct ldh_tail : star<sor<seq<plus<one<'-'>>, let_dig>, let_dig>> {};

struct ldh_str : seq<let_dig, ldh_tail> {};

// struct label : seq<let_dig, opt<ldh_str>> {};

struct sub_domain : u_label {};

struct domain : list_tail<sub_domain, dot> {};

struct dec_octet : sor<seq<string<'2','5'>, range<'0','5'>>,
                       seq<one<'2'>, range<'0','4'>, DIGIT>,
                       seq<range<'0', '1'>, rep<2, DIGIT>>,
                       rep_min_max<1, 2, DIGIT>> {};

struct IPv4_address_literal
    : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {};

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

// See rfc 5321 Section 4.1.3
struct address_literal : seq<one<'['>,
                             sor<IPv4_address_literal,
                                 IPv6_address_literal,
                                 general_address_literal>,
                             one<']'>> {};

struct at_domain : seq<one<'@'>, domain> {};

struct a_d_l : list<at_domain, one<','>> {};

// The qtextSMTP rule explained: it's ASCII...
// excluding all the control chars below SPACE
//           34 '"' the double quote
//           92 '\\' the back slash
//           DEL
// So including:
// 32-33:  ' ' and '!'
// 35-91:  "#$%&'()*+,-./" 0-9 ":;<=>?@"  A-Z  '['
// 93-126: "]^_`"  a-z  "{|}~"

struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, UTF8_non_ascii> {};

struct graphic : range<32, 126> {};

struct quoted_pairSMTP : seq<one<'\\'>, graphic> {};

struct qcontentSMTP : sor<qtextSMTP, quoted_pairSMTP> {};

struct quoted_string : seq<one<'"'>, star<qcontentSMTP>, one<'"'>> {};

// excluded from atext are the “specials”: "()<>[]:;@\\,."

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
                   UTF8_non_ascii> {};

struct atom : plus<atext> {};

struct dot_string : list<atom, dot> {};

struct local_part : sor<dot_string, quoted_string> {};

struct non_local_part : sor<domain, address_literal> {};

struct mailbox : seq<local_part, one<'@'>, non_local_part> {};

struct path : seq<one<'<'>, seq<opt<seq<a_d_l, colon>>, mailbox, one<'>'>>> {};

struct bounce_path : TAO_PEGTL_ISTRING("<>") {};

struct reverse_path : sor<path, bounce_path> {};

struct magic_postmaster : TAO_PEGTL_ISTRING("<Postmaster>") {};

struct forward_path : sor<path, magic_postmaster> {};

struct esmtp_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash>>> {};

struct esmtp_value : plus<sor<range<33, 60>, range<62, 126>, UTF8_non_ascii>> {};

struct esmtp_param : seq<esmtp_keyword, opt<seq<one<'='>, esmtp_value>>> {};

struct mail_parameters : list<esmtp_param, SP> {};

struct rcpt_parameters : list<esmtp_param, SP> {};

struct string : sor<quoted_string, atom> {};

struct helo : seq<TAO_PEGTL_ISTRING("HELO"),
                  SP,
                  sor<domain, address_literal>,
                  CRLF> {};

struct ehlo : seq<TAO_PEGTL_ISTRING("EHLO"),
                  SP,
                  sor<domain, address_literal>,
                  CRLF> {};

struct mail_from : seq<TAO_PEGTL_ISTRING("MAIL"),
                       TAO_PEGTL_ISTRING(" FROM:"),
                       opt<SP>, // obsolete in RFC5321, but kosher in RFC821
                       reverse_path,
                       opt<seq<SP, mail_parameters>>,
                       CRLF> {};

struct rcpt_to : seq<TAO_PEGTL_ISTRING("RCPT"),
                     TAO_PEGTL_ISTRING(" TO:"),
                     opt<SP>, // obsolete in RFC5321, but kosher in RFC821
                     forward_path,
                     opt<seq<SP, rcpt_parameters>>,
                     CRLF> {};

struct chunk_size : plus<DIGIT> {};

struct end_marker : TAO_PEGTL_ISTRING(" LAST") {};

struct bdat : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, CRLF> {};

struct bdat_last
    : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, end_marker, CRLF> {};

struct data : seq<TAO_PEGTL_ISTRING("DATA"), CRLF> {};

struct data_end : seq<dot, CRLF> {};

struct data_blank : CRLF {};

// Rules for strict RFC adherence:

// RFC 5321 text line length section 4.5.3.1.6.
struct data_dot
    : seq<one<'.'>, rep_min_max<1, 998, not_one<'\r', '\n'>>, CRLF> {};

struct data_plain : seq<rep_min_max<1, 998, not_one<'\r', '\n'>>, CRLF> {};

// But let's accept real-world crud, up to a point...

struct anything_else : seq<star<not_one<'\n'>>, one<'\n'>> {};

// This particular crud will trigger an error return with the "no bare
// LF" message.

struct not_data_end : seq<dot, LF> {};

struct data_line : sor<at<data_end>,
                       seq<sor<data_blank,
                               data_dot,
                               data_plain,
                               not_data_end,
                               anything_else>,
                           discard>> {};

struct data_grammar : until<data_end, data_line> {};

struct rset : seq<TAO_PEGTL_ISTRING("RSET"), CRLF> {};

struct noop : seq<TAO_PEGTL_ISTRING("NOOP"), opt<seq<SP, string>>, CRLF> {};

struct vrfy : seq<TAO_PEGTL_ISTRING("VRFY"), opt<seq<SP, string>>, CRLF> {};

struct help : seq<TAO_PEGTL_ISTRING("HELP"), opt<seq<SP, string>>, CRLF> {};

struct starttls
    : seq<TAO_PEGTL_ISTRING("STAR"), TAO_PEGTL_ISTRING("TTLS"), CRLF> {};

struct quit : seq<TAO_PEGTL_ISTRING("QUIT"), CRLF> {};

// Anti-AUTH support

// base64-char     = ALPHA / DIGIT / "+" / "/"
//                   ;; Case-sensitive

struct base64_char : sor<ALPHA, DIGIT, one<'+', '/'>> {};

// base64-terminal = (2base64-char "==") / (3base64-char "=")

struct base64_terminal : sor<seq<rep<2, base64_char>, TAO_PEGTL_ISTRING("==")>,
                             seq<rep<3, base64_char>, one<'='>>
                             > {};

// base64          = base64-terminal /
//                   ( 1*(4base64-char) [base64-terminal] )

struct base64 : sor<base64_terminal,
                    seq<plus<rep<4, base64_char>>,
                        opt<base64_terminal>>
                    > {};

// initial-response= base64 / "="

struct initial_response : sor<base64, one<'='>> {};

// cancel-response = "*"

struct cancel_response : one<'*'> {};

struct UPPER_ALPHA : range<'A', 'Z'> {};

using HYPHEN = one<'-'>;
using UNDERSCORE = one<'_'>;

struct mech_char : sor<UPPER_ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct sasl_mech : rep_min_max<1, 20, mech_char> {};

// auth-command    = "AUTH" SP sasl-mech [SP initial-response]
//                   *(CRLF [base64]) [CRLF cancel-response]
//                   CRLF
//                   ;; <sasl-mech> is defined in RFC 4422

struct auth : seq<TAO_PEGTL_ISTRING("AUTH"), SP, sasl_mech,
                  opt<seq<SP, initial_response>>,
                  // star<CRLF, opt<base64>>,
                  // opt<seq<CRLF, cancel_response>>,
                  CRLF> {};
// bad commands:

struct bogus_cmd_short : seq<rep_min_max<0, 3, not_one<'\r', '\n'>>, CRLF> {};
struct bogus_cmd_long : seq<rep_min_max<4, 1000, not_one<'\r', '\n'>>, CRLF> {};

// commands in size order

struct any_cmd : seq<sor<bogus_cmd_short,
                         data,
                         quit,
                         rset,
                         noop,
                         vrfy,
                         help,
                         helo,
                         ehlo,
                         bdat,
                         bdat_last,
                         starttls,
                         rcpt_to,
                         mail_from,
                         auth,
                         bogus_cmd_long,
                         anything_else>,
                     discard> {};

struct grammar : plus<any_cmd> {};

// clang-format on

template <typename Rule>
struct action : nothing<Rule> {
};

template <typename Rule>
struct data_action : nothing<Rule> {
};

template <>
struct action<esmtp_keyword> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.param.first = in.string();
  }
};

template <>
struct action<bogus_cmd_short> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(INFO) << "bogus_cmd_short";
    ctx.session.cmd_unrecognized(in.string());
  }
};

template <>
struct action<bogus_cmd_long> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(INFO) << "bogus_cmd_long";
    ctx.session.cmd_unrecognized(in.string());
  }
};

template <>
struct action<anything_else> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(INFO) << "anything_else";
    ctx.session.cmd_unrecognized(in.string());
  }
};

template <>
struct action<esmtp_value> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.param.second = in.string();
  }
};

template <>
struct action<esmtp_param> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.parameters.insert(ctx.param);
    ctx.param.first.clear();
    ctx.param.second.clear();
  }
};

template <>
struct action<local_part> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.mb_loc = in.string();
    // RFC 5321, section 4.5.3.1.1.
    if (ctx.mb_loc.length() > 64) {
      LOG(WARNING) << "local part too long " << ctx.mb_loc;
    }
  }
};

template <>
struct action<non_local_part> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.mb_dom = in.string();
    // RFC 5321, section 4.5.3.1.2.
    if (ctx.mb_dom.length() > 255) {
      LOG(WARNING) << "domain name or number too long " << ctx.mb_dom;
    }
  }
};

template <>
struct action<magic_postmaster> {
  static void apply0(Ctx& ctx)
  {
    ctx.mb_loc = std::string{"Postmaster"};
    ctx.mb_dom.clear();
  }
};

template <>
struct action<helo> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const b = begin(in) + 5; // +5 for the length of "HELO "
    auto const e = std::find(b, end(in) - 2, ' '); // -2 for the CRLF
    ctx.session.helo(std::string_view(b, e - b));
  }
};

template <>
struct action<ehlo> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const b = begin(in) + 5; // +5 for the length of "EHLO "
    auto const e = std::find(b, end(in) - 2, ' '); // -2 for the CRLF
    ctx.session.ehlo(std::string_view(b, e - b));
  }
};

template <>
struct action<mail_from> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.mail_from(Mailbox{ctx.mb_loc, ctx.mb_dom}, ctx.parameters);
    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
    ctx.parameters.clear();
  }
};

template <>
struct action<rcpt_to> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.rcpt_to(Mailbox{ctx.mb_loc, ctx.mb_dom}, ctx.parameters);
    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
    ctx.parameters.clear();
  }
};

template <>
struct action<chunk_size> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.chunk_size = std::strtoull(in.string().c_str(), nullptr, 10);
  }
};

bool bdat_act(Ctx& ctx)
{
  auto ret = ctx.session.bdat_start(ctx.chunk_size);

  auto to_xfer = ctx.chunk_size;

  auto const bfr_size{std::min(to_xfer, std::streamsize(FLAGS_max_xfer_size))};
  iobuffer<char> bfr(bfr_size);

  while (to_xfer) {
    auto const xfer_sz{std::min(to_xfer, bfr_size)};

    ctx.session.in().read(bfr.data(), xfer_sz);
    if (!ctx.session.in()) {
      LOG(ERROR) << "attempt to read " << xfer_sz << " octets but only got "
                 << ctx.session.in().gcount();
      if (ctx.session.maxed_out()) {
        LOG(ERROR) << "input maxed out";
        ctx.session.bdat_size_error();
        return false;
      }
      if (ctx.session.timed_out()) {
        LOG(ERROR) << "input timed out";
      }
      if (ctx.session.in().eof()) {
        LOG(ERROR) << "EOF in BDAT";
      }
      ctx.session.bdat_error();
      return false;
    }
    if (!ctx.session.msg_write(bfr.data(), xfer_sz))
      ret = false;

    to_xfer -= xfer_sz;
  }

  return ret;
}

template <>
struct action<bdat> {
  static void apply0(Ctx& ctx)
  {
    if (bdat_act(ctx))
      ctx.session.bdat_done(ctx.chunk_size, false);
  }
};

template <>
struct action<bdat_last> {
  static void apply0(Ctx& ctx)
  {
    if (bdat_act(ctx))
      ctx.session.bdat_done(ctx.chunk_size, true);
  }
};

template <>
struct data_action<data_end> {
  static void apply0(Ctx& ctx) { ctx.session.data_done(); }
};

template <>
struct data_action<data_blank> {
  static void apply0(Ctx& ctx)
  {
    constexpr char CRLF[]{'\r', '\n'};
    ctx.session.msg_write(CRLF, sizeof(CRLF));
  }
};

template <>
struct data_action<data_plain> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const len{end(in) - begin(in)};
    ctx.session.msg_write(begin(in), len);
  }
};

template <>
struct data_action<data_dot> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const len{end(in) - begin(in) - 1};
    ctx.session.msg_write(begin(in) + 1, len);
  }
};

template <>
struct data_action<not_data_end> {
  static void apply0(Ctx& ctx) __attribute__((noreturn))
  {
    ctx.session.bare_lf();
  }
};

template <>
struct data_action<anything_else> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(WARNING) << "garbage in data stream: \"" << esc(in.string()) << "\"";
    auto const len{end(in) - begin(in)};
    if (len)
      ctx.session.msg_write(begin(in), len);
    if (len > 1000) {
      LOG(WARNING) << "line too long at " << len << " octets";
    }
  }
};

template <>
struct action<data> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    if (ctx.session.data_start()) {
      auto din = istream_input<eol::crlf>(ctx.session.in(), FLAGS_bfr_size,
                                          "data");
      try {
        if (!parse_nested<RFC5321::data_grammar, RFC5321::data_action>(in, din,
                                                                       ctx)) {
          ctx.session.log_stats();
          if (!(ctx.session.maxed_out() || ctx.session.timed_out())) {
            ctx.session.error("bad DATA syntax");
          }
        }
        return;
      }
      catch (parse_error const& e) {
        LOG(WARNING) << e.what();
        ctx.session.error("unable to parse DATA stream");
      }
      catch (std::exception const& e) {
        LOG(WARNING) << e.what();
        ctx.session.error("unknown problem in DATA stream");
      }
    }
  }
};

template <>
struct action<rset> {
  static void apply0(Ctx& ctx) { ctx.session.rset(); }
};

template <typename Input>
std::string_view get_string_view(Input const& in)
{
  auto const b   = begin(in) + 4;
  auto const len = end(in) - b;
  auto       str = std::string_view(b, len);
  if (str.front() == ' ')
    str.remove_prefix(1);
  return str;
}

template <>
struct action<noop> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const str = get_string_view(in);
    ctx.session.noop(str);
  }
};

template <>
struct action<vrfy> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const str = get_string_view(in);
    ctx.session.vrfy(str);
  }
};

template <>
struct action<help> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const str = get_string_view(in);
    ctx.session.help(str);
  }
};

template <>
struct action<starttls> {
  static void apply0(Ctx& ctx) { ctx.session.starttls(); }
};

template <>
struct action<quit> {
  static void apply0(Ctx& ctx) __attribute__((noreturn)) { ctx.session.quit(); }
};

template <>
struct action<auth> {
  static void apply0(Ctx& ctx) __attribute__((noreturn)) { ctx.session.auth(); }
};
} // namespace RFC5321

void timeout(int signum) __attribute__((noreturn));
void timeout(int signum)
{
  const char errmsg[] = "421 4.4.2 time-out\r\n";
  write(STDOUT_FILENO, errmsg, sizeof errmsg - 1);
  _Exit(1);
}

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);

  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  // Set timeout signal handler to limit total run time.
  struct sigaction sact {
  };
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags   = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);
  alarm(2 * 60); // initial alarm

  auto const log_dir{getenv("GOOGLE_LOG_DIR")};
  if (log_dir) {
    error_code ec;
    fs::create_directories(log_dir, ec);
  }

  google::InitGoogleLogging(argv[0]);

  std::unique_ptr<RFC5321::Ctx> ctx;

  // Don't wait for STARTTLS to fail if no cert.
  auto const config_path = osutil::get_config_dir();
  auto const certs = osutil::list_directory(config_path, Config::cert_fn_re);
  CHECK_GE(certs.size(), 1) << "no certs found";

  auto const read_hook{[&ctx]() { ctx->session.flush(); }};
  ctx = std::make_unique<RFC5321::Ctx>(config_path, read_hook);

  ctx->session.greeting();

  istream_input<eol::crlf> in{ctx->session.in(), FLAGS_bfr_size, "session"};

  int ret = 0;
  try {
    ret = !parse<RFC5321::grammar, RFC5321::action>(in, *ctx);
  }
  catch (std::exception const& e) {
    LOG(WARNING) << e.what();
  }

  if (ctx->session.maxed_out()) {
    ctx->session.max_out();
  }
  else if (ctx->session.timed_out()) {
    ctx->session.time_out();
  }
  // else {
  //   ctx->session.error("session end without QUIT command from client");
  // }

  return ret;
}

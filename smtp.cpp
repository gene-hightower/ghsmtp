#include <gflags/gflags.h>
namespace gflags {
}

// These need to be at least the length of any string it's trying to match.
DEFINE_uint64(cmd_bfr_size, 4 * 1024, "command parser buffer size");
DEFINE_uint64(data_bfr_size, 64 * 1024, "data parser buffer size");

DEFINE_uint64(max_xfer_size, 64 * 1024, "maximum BDAT transfer size");

constexpr auto smtp_max_line_length = 1000;
constexpr auto smtp_max_str_length =
    smtp_max_line_length - 2; // length of line without CRLF

#include <seccomp.h>

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

using namespace std::string_literals;

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

#include "UTF8.hpp"

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {};

using dot   = one<'.'>;
using colon = one<':'>;
using dash  = one<'-'>;

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
                       seq<one<'1'>, rep<2, DIGIT>>,
                       seq<range<'1', '9'>, DIGIT>,
                       DIGIT
                      > {};
struct IPv4_address_literal
    : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {};

struct h16 : rep_min_max<1, 4, HEXDIG> {};

struct ls32 : sor<seq<h16, colon, h16>, IPv4_address_literal> {};

struct dcolon : two<':'> {};

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

struct IPv6_address_literal : seq<TAO_PEGTL_ISTRING("I"),
                                  TAO_PEGTL_ISTRING("P"),
                                  TAO_PEGTL_ISTRING("v"),
                                  one<'6'>,
                                  one<':'>,
                                  IPv6address> {};

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

struct quoted_string : seq<one<'"'>, plus<qcontentSMTP>, one<'"'>> {};

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

struct path : seq<one<'<'>, mailbox, one<'>'>> {};

struct bounce_path : seq<one<'<'>, one<'>'>> {};

struct reverse_path : sor<path, bounce_path> {};

struct magic_postmaster : seq<one<'<'>,
                              TAO_PEGTL_ISTRING("P"),
                              TAO_PEGTL_ISTRING("o"),
                              TAO_PEGTL_ISTRING("s"),
                              TAO_PEGTL_ISTRING("t"),
                              TAO_PEGTL_ISTRING("m"),
                              TAO_PEGTL_ISTRING("a"),
                              TAO_PEGTL_ISTRING("s"),
                              TAO_PEGTL_ISTRING("t"),
                              TAO_PEGTL_ISTRING("e"),
                              TAO_PEGTL_ISTRING("r"),
                              one<'>'>> {};

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
                       seq<one<' '>,
                           TAO_PEGTL_ISTRING("F"),
                           TAO_PEGTL_ISTRING("R"),
                           TAO_PEGTL_ISTRING("O"),
                           TAO_PEGTL_ISTRING("M"),
                           one<':'>>,
                       opt<SP>, // common enough error, we'll allow it
                       reverse_path,
                       opt<seq<SP, mail_parameters>>,
                       CRLF> {};

// clang-format off
struct rcpt_to : seq<TAO_PEGTL_ISTRING("RCPT"),
                       seq<one<' '>,
                           TAO_PEGTL_ISTRING("T"),
                           TAO_PEGTL_ISTRING("O"),
                           one<':'>>,
                     opt<SP>, // common enough error, we'll allow it
                     forward_path,
                     opt<seq<SP, rcpt_parameters>>,
                     CRLF> {};
// clang-format on

struct chunk_size : plus<DIGIT> {};

struct last : TAO_PEGTL_ISTRING("LAST") {};

struct bdat : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, CRLF> {};

struct bdat_last : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, SP, last, CRLF> {};

struct data : seq<TAO_PEGTL_ISTRING("DATA"), CRLF> {};

// ## below: DATA sub parse ##

struct data_end : seq<dot, CRLF> {};

struct data_blank : CRLF {};

// This particular crud will trigger an error return with the "no bare
// LF" message.

struct data_not_end : seq<dot, LF> {};

struct data_also_not_end : seq<LF, dot, CRLF> {};


// RFC 5321 text line length section 4.5.3.1.6.
struct data_plain
  : seq<rep_min_max<1, smtp_max_str_length, not_one<'\r', '\n'>>, CRLF> {};

struct data_dot : seq<one<'.'>,
                      rep_min_max<1, smtp_max_str_length, not_one<'\r', '\n'>>,
                      CRLF> {};

struct data_long : seq<star<not_one<'\r', '\n'>>, CRLF> {};

struct data_line : seq<sor<data_blank,
                           data_not_end,
                           data_also_not_end,
                           data_dot,
                           data_plain,
                           data_long>,
                       discard> {};

struct data_grammar : until<data_end, data_line> {};

// ## above: DATA sub parse ##

struct rset : seq<TAO_PEGTL_ISTRING("RSET"), CRLF> {};

struct noop : seq<TAO_PEGTL_ISTRING("NOOP"), opt<seq<SP, string>>, CRLF> {};

struct vrfy : seq<TAO_PEGTL_ISTRING("VRFY"), opt<seq<SP, string>>, CRLF> {};

struct help : seq<TAO_PEGTL_ISTRING("HELP"), opt<seq<SP, string>>, CRLF> {};

struct starttls : seq<TAO_PEGTL_ISTRING("STAR"),
                      seq<TAO_PEGTL_ISTRING("T"),
                          TAO_PEGTL_ISTRING("T"),
                          TAO_PEGTL_ISTRING("L"),
                          TAO_PEGTL_ISTRING("S")>,
                      CRLF> {};

struct quit : seq<TAO_PEGTL_ISTRING("QUIT"), CRLF> {};

// Anti-AUTH support

// base64-char     = ALPHA / DIGIT / "+" / "/"
//                   ;; Case-sensitive

struct base64_char : sor<ALPHA, DIGIT, one<'+', '/'>> {};

// base64-terminal = (2base64-char "==") / (3base64-char "=")

struct base64_terminal : sor<seq<rep<2, base64_char>, one<'='>, one<'='>>,
                             seq<rep<3, base64_char>, one<'='>>> {};

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

// Bad commands; the short one is to matched first, and the long one
// last, after all valid command have been tried.

struct bogus_cmd_short : seq<rep_min_max<0, 3, not_one<'\r', '\n'>>, CRLF> {};
struct bogus_cmd_long
  : seq<rep_min_max<4, smtp_max_line_length, not_one<'\r', '\n'>>, CRLF> {};

// Command matches after bogus_cmd_short can assume to have 4 or more
// chars before the CRLF, so can use TAO_PEGTL_ISTRING<"XXXX"> in the
// initial seq.  Command order in this list doesn't matter beyond all
// valid command after bogus short and before bogus last.

struct any_cmd : seq<sor<bogus_cmd_short,

                         helo,
                         ehlo,

                         starttls,

                         auth,
                         help,
                         noop,
                         quit,
                         rset,
                         vrfy,

                         data,

                         bdat,
                         bdat_last,

                         mail_from,
                         rcpt_to,

                         bogus_cmd_long>,
                     discard> {};

struct grammar : plus<any_cmd> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <typename Rule>
struct data_action : nothing<Rule> {
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
struct action<esmtp_keyword> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.param.first = in.string();
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
      LOG(INFO) << "local part «" << ctx.mb_loc
                << "» length == " << ctx.mb_loc.length();
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
    if (ctx.mb_dom.length() > 253) {
      LOG(WARNING) << "domain name too long " << ctx.mb_dom;
    }
  }
};

template <>
struct action<bounce_path> {
  static void apply0(Ctx& ctx)
  {
    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
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
    Mailbox mbx;

    if (ctx.mb_loc != ""s && ctx.mb_dom != ""s) {
      mbx = Mailbox{ctx.mb_loc, Domain{ctx.mb_dom}};
    }
    ctx.session.mail_from(std::move(mbx), ctx.parameters);
    ctx.mb_loc.clear();
    ctx.mb_dom.clear();
    ctx.parameters.clear();
  }
};

template <>
struct action<rcpt_to> {
  static void apply0(Ctx& ctx)
  {
    Mailbox mbx;

    if (ctx.mb_loc == "Postmaster"s) {
      mbx = Mailbox{"Postmaster"};
    }
    else {
      mbx = Mailbox{ctx.mb_loc, Domain{ctx.mb_dom}};
    }
    ctx.session.rcpt_to(std::move(mbx), ctx.parameters);
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

void bdat_act(Ctx& ctx, bool last)
{
  auto status_returned = false;

  if (!ctx.session.bdat_start(ctx.chunk_size))
    status_returned = true;

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
        if (!status_returned)
          ctx.session.bdat_size_error();
      }
      else if (ctx.session.timed_out()) {
        LOG(ERROR) << "input timed out";
        if (!status_returned)
          ctx.session.bdat_io_error();
      }
      else if (ctx.session.in().eof()) {
        LOG(ERROR) << "EOF in BDAT";
        if (!status_returned)
          ctx.session.bdat_io_error();
      }
      else {
        LOG(ERROR) << "I/O error in BDAT";
        if (!status_returned)
          ctx.session.bdat_io_error();
      }
      return;
    }
    if (!status_returned && !ctx.session.msg_write(bfr.data(), xfer_sz)) {
      status_returned = true;
    }

    to_xfer -= xfer_sz;
  }

  if (!status_returned) {
    ctx.session.bdat_done(ctx.chunk_size, last);
  }
}

template <>
struct action<bdat> {
  static void apply0(Ctx& ctx)
  {
    bdat_act(ctx, false);
  }
};

template <>
struct action<bdat_last> {
  static void apply0(Ctx& ctx)
  {
    bdat_act(ctx, true);
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
struct data_action<data_long> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(WARNING) << "garbage in data stream: \"" << esc(in.string()) << "\"";
    auto const len{end(in) - begin(in)};
    if (len)
      ctx.session.msg_write(begin(in), len);
    if (len > smtp_max_line_length) {
      LOG(WARNING) << "line too long at " << len << " octets";
    }
  }
};

template <>
struct data_action<data_not_end> {
  static void apply0(Ctx& ctx) __attribute__((noreturn))
  {
    ctx.session.bare_lf();
  }
};

template <>
struct data_action<data_also_not_end> {
  static void apply0(Ctx& ctx) __attribute__((noreturn))
  {
    ctx.session.bare_lf();
  }
};

template <>
struct action<data> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    if (ctx.session.data_start()) {
      auto din = istream_input<eol::crlf, 1>(ctx.session.in(),
                                             FLAGS_data_bfr_size, "data");
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

void install_syscall_filter()
{
  /// scmp_filter_ctx ctx = CHECK_NOTNULL(seccomp_init(SCMP_ACT_ERRNO(EPERM)));
  scmp_filter_ctx ctx = CHECK_NOTNULL(seccomp_init(SCMP_ACT_LOG));

  auto rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add write failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add read failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add close failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add rt_sigprocmask failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add rt_sigreturn failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add rt_sigaction failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add fstat failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add openat failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add socket failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add connect failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add poll failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add sendto failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add recvfrom failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add sigaltstack failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add prctl failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add gettid failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add getpid failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add getppid failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add newfstatat failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add tgkill failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add dup failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add mmap failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add munmap failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add pipe2 failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add readlinkat failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add pselect6 failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add uname failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add fcntl failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add unlink failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add symlink failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add madvise failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add mprotect failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add futex failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add writev failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add sysinfo failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add brk failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add getrandom failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add getdents64 failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add lseek failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add setsockopt failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add alarm failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add rename failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add clock_gettime failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add exit_group failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add exit failed";

  // for sanitize

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add clone failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add wait4 failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add sched_yield failed";

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ptrace), 0);
  CHECK_EQ(rc, 0) << "seccomp_rule_add ptrace failed";

  rc = seccomp_load(ctx);
  CHECK_EQ(rc, 0) << "seccomp_load failed";

  // seccomp_export_pfc(ctx, STDERR_FILENO);

  seccomp_release(ctx);
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
  struct sigaction sact {};
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags   = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);

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

  install_syscall_filter();

  istream_input<eol::crlf, 1> in{ctx->session.in(), FLAGS_cmd_bfr_size,
                                 "session"};

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

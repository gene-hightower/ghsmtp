#include <gflags/gflags.h>
namespace gflags {
}

// These need to be at least the length of any string it's trying to match.
DEFINE_uint64(cmd_bfr_size, 4 * 1024, "command parser buffer size");
DEFINE_uint64(data_bfr_size, 64 * 1024, "data parser buffer size");

DEFINE_uint64(max_xfer_size, 64 * 1024, "maximum BDAT transfer size");

DEFINE_bool(close_stderr, false, "ignored");
DEFINE_bool(server, false, "listen and accept");
DEFINE_bool(soc_debug, false, "socket debug flag");

DEFINE_string(bind, "localhost", "bind address");
DEFINE_string(service, "smtp", "service name");

constexpr auto smtp_max_line_length = 1000;
constexpr auto smtp_max_str_length =
    smtp_max_line_length - 2; // length of line without CRLF

#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "Session.hpp"
#include "esc.hpp"
#include "fs.hpp"
#include "iobuffer.hpp"
#include "osutil.hpp"

#include <cstdlib>
#include <fstream>
#include <memory>
#include <stdexcept>

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/ranges.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

// Process exit codes, the EXIT_BAD_xxx codes taint the sender.
enum {
  EXIT_ = 32,             // sort all the others past this one
  EXIT_AUTH_FAIL,         // we don't support AUTH
  EXIT_BAD_GREETING,      // pre-greeting traffic
  EXIT_BAD_IP_ADDRESS,    // failed at connect, DNSBL
  EXIT_BAD_LO,            // error from helo/ehlo
  EXIT_BAD_MAIL_FROM,     // verify_sender_ returned false
  EXIT_BARE_LF,           // hard fail on bare '\n'
  EXIT_EXCPETION,         // unknown exception
  EXIT_IO_TIME_OUT,       // too much time waiting for read or write
  EXIT_MAXED_OUT,         // too much data
  EXIT_NO_DATA,           // zero length random garbage
  EXIT_RANDOM_GARBAGE,    // not even a text line ending in CRLF
  EXIT_SMTP_SYNTAX_ERROR, // some protocol parser error
  EXIT_TIME_OUT,          // too much time overall
  EXIT_TOO_MANY_BAD_CMDS, // eventually, we cut them off
};

std::string exit_as_text(int ret)
{
  switch (ret) { // clang-format off
  case EXIT_AUTH_FAIL:         return "AUTH_FAIL";
  case EXIT_BAD_GREETING:      return "BAD_GREETING";
  case EXIT_BAD_IP_ADDRESS:    return "BAD_IP_ADDRESS";
  case EXIT_BAD_LO:            return "BAD_LO";
  case EXIT_BAD_MAIL_FROM:     return "BAD_MAIL_FROM";
  case EXIT_BARE_LF:           return "BARE_LF";
  case EXIT_EXCPETION:         return "EXCPETION";
  case EXIT_IO_TIME_OUT:       return "IO_TIME_OUT";
  case EXIT_MAXED_OUT:         return "MAXED_OUT";
  case EXIT_NO_DATA:           return "NO_DATA";
  case EXIT_RANDOM_GARBAGE:    return "RANDOM_GARBAGE";
  case EXIT_SMTP_SYNTAX_ERROR: return "SMTP_SYNTAX_ERROR";
  case EXIT_SUCCESS:           return "SUCCESS";
  case EXIT_TIME_OUT:          return "TIME_OUT";
  case EXIT_TOO_MANY_BAD_CMDS: return "TOO_MANY_BAD_CMDS";
  } // clang-format on
  return fmt::format("{}", ret);
}

[[noreturn]] void smtp_exit(int ret)
{
  CHECK_GE(ret, 0);
  CHECK_LE(ret, 0xff); // on unixen
  timespec time_used{};
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_used);

  LOG(INFO) << "CPU time " << time_used.tv_sec << "." << std::setw(9)
            << std::setfill('0') << time_used.tv_nsec << " seconds";

  std::exit(ret);
}

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

struct dec_octet : sor<seq<string<'2', '5'>, range<'0', '5'>>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<one<'1'>, rep<2, DIGIT>>,
                       seq<range<'1', '9'>, DIGIT>,
                       DIGIT> {};
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

struct general_address_literal : seq<standardized_tag, colon, plus<dcontent>> {
};

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

// clang-format off
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
// clang-format on

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

struct esmtp_value : plus<sor<range<33, 60>, range<62, 126>, UTF8_non_ascii>> {
};

struct esmtp_param : seq<esmtp_keyword, opt<seq<one<'='>, esmtp_value>>> {};

struct mail_parameters : list<esmtp_param, SP> {};

struct rcpt_parameters : list<esmtp_param, SP> {};

struct string : sor<quoted_string, atom> {};

struct helo
  : seq<TAO_PEGTL_ISTRING("HELO"), SP, sor<domain, address_literal>, CRLF> {};

struct ehlo
  : seq<TAO_PEGTL_ISTRING("EHLO"), SP, sor<domain, address_literal>, CRLF> {};

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

struct bdat_last
  : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, SP, last, CRLF> {};

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

struct base64
  : sor<base64_terminal, seq<plus<rep<4, base64_char>>, opt<base64_terminal>>> {
};

// initial-response= base64 / "="

struct initial_response : sor<base64, one<'='>> {};

// cancel-response = "*"

struct cancel_response : one<'*'> {};

struct UPPER_ALPHA : range<'A', 'Z'> {};

using HYPHEN     = one<'-'>;
using UNDERSCORE = one<'_'>;

struct mech_char : sor<UPPER_ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct sasl_mech : rep_min_max<1, 20, mech_char> {};

// auth-command    = "AUTH" SP sasl-mech [SP initial-response]
//                   *(CRLF [base64]) [CRLF cancel-response]
//                   CRLF
//                   ;; <sasl-mech> is defined in RFC 4422

struct auth : seq<TAO_PEGTL_ISTRING("AUTH"),
                  SP,
                  sasl_mech,
                  opt<seq<SP, initial_response>>,
                  // star<CRLF, opt<base64>>,
                  // opt<seq<CRLF, cancel_response>>,
                  CRLF> {};

// Bad commands; the short one is to matched first, and the long one
// last, after all valid command have been tried.

struct bogus_cmd_short : seq<rep_min_max<0, 3, not_one<'\r', '\n'>>, CRLF> {};
struct bogus_cmd_long
  : seq<rep_min_max<4, smtp_max_str_length, not_one<'\r', '\n'>>, CRLF> {};
struct random_garbage : rep_min_max<0, smtp_max_line_length, any> {};

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

                         bogus_cmd_long,

                         random_garbage>,
                     discard> {};

struct grammar : plus<any_cmd> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <typename Rule>
struct data_action : nothing<Rule> {};

template <>
struct action<bogus_cmd_short> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(INFO) << "bogus_cmd_short";
    if (!ctx.session.cmd_unrecognized(in.string())) {
      smtp_exit(EXIT_TOO_MANY_BAD_CMDS);
    }
  }
};

template <>
struct action<bogus_cmd_long> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(INFO) << "bogus_cmd_long";
    if (!ctx.session.cmd_unrecognized(in.string())) {
      smtp_exit(EXIT_TOO_MANY_BAD_CMDS);
    }
  }
};

template <>
struct action<random_garbage> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    if (in.string().size()) {
      if (!ctx.session.random_garbage(in.string())) {
        LOG(INFO) << "random_garbage";
        smtp_exit(EXIT_RANDOM_GARBAGE);
      }
    }
    smtp_exit(EXIT_NO_DATA);
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
    CHECK_GT(end(in) - begin(in), 5);
    auto const b = begin(in) + 5; // +5 for the length of "HELO "
    auto const e = std::find(b, end(in) - 2, ' '); // -2 for the CRLF
    if (!ctx.session.helo(std::string_view(b, e - b))) {
      smtp_exit(EXIT_BAD_LO);
    }
  }
};

template <>
struct action<ehlo> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    CHECK_GT(end(in) - begin(in), 5);
    auto const b = begin(in) + 5; // +5 for the length of "EHLO "
    auto const e = std::find(b, end(in) - 2, ' '); // -2 for the CRLF
    if (!ctx.session.ehlo(std::string_view(b, e - b))) {
      smtp_exit(EXIT_BAD_LO);
    }
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
    if (!ctx.session.mail_from(std::move(mbx), ctx.parameters)) {
      smtp_exit(EXIT_BAD_MAIL_FROM);
    }
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
      mbx = Mailbox("Postmaster");
    }
    else {
      mbx = Mailbox(ctx.mb_loc, Domain(ctx.mb_dom));
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

  auto const bfr_size(std::min(to_xfer, std::streamsize(FLAGS_max_xfer_size)));
  iobuffer<char> bfr(bfr_size);

  while (to_xfer) {
    auto const xfer_sz(std::min(to_xfer, bfr_size));

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
  static void apply0(Ctx& ctx) { bdat_act(ctx, false); }
};

template <>
struct action<bdat_last> {
  static void apply0(Ctx& ctx) { bdat_act(ctx, true); }
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
    auto const len(end(in) - begin(in));
    ctx.session.msg_write(begin(in), len);
  }
};

template <>
struct data_action<data_dot> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto const len(end(in) - begin(in) - 1);
    ctx.session.msg_write(begin(in) + 1, len);
  }
};

template <>
struct data_action<data_long> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(WARNING) << "garbage in data stream: \"" << esc(in.string()) << "\"";
    auto const len(end(in) - begin(in));
    if (len)
      ctx.session.msg_write(begin(in), len);
    if (len > smtp_max_line_length) {
      LOG(WARNING) << "line too long at " << len << " octets";
    }
  }
};

template <>
struct data_action<data_not_end> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.bare_lf();
    smtp_exit(EXIT_BARE_LF);
  }
};

template <>
struct data_action<data_also_not_end> {
  static void apply0(Ctx& ctx)
  {
    ctx.session.bare_lf();
    smtp_exit(EXIT_BARE_LF);
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
  CHECK_GT(end(in) - begin(in), 4);
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
  [[noreturn]] static void apply0(Ctx& ctx)
  {
    ctx.session.quit();
    smtp_exit(EXIT_SUCCESS);
  }
};

template <>
struct action<auth> {
  [[noreturn]] static void apply0(Ctx& ctx)
  {
    ctx.session.auth();
    smtp_exit(EXIT_AUTH_FAIL);
  }
};
} // namespace RFC5321

[[noreturn]] void timeout(int signum)
{
  const char errmsg[] = "421 4.4.2 time-out\r\n";
  (void)write(STDOUT_FILENO, errmsg, sizeof errmsg - 1);
  (void)close(STDOUT_FILENO);
  smtp_exit(EXIT_TIME_OUT);
}

static volatile bool sig_hup  = false;
static volatile bool sig_quit = false;

void sighup(int signum) { sig_hup = true; }
void sigquit(int signum) { sig_quit = true; }

// Process an SMTP session from a connecting client.

int session()
{
  // Set timeout signal handler to limit total run time.
  struct sigaction sact{};
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags   = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);

  auto const config_path = osutil::get_config_dir();

  std::unique_ptr<RFC5321::Ctx> ctx;
  try {
    auto const read_hook{[&ctx]() { ctx->session.flush(); }};
    ctx = std::make_unique<RFC5321::Ctx>(config_path, read_hook);

    if (!ctx->session.pre_greeting())
      return EXIT_BAD_IP_ADDRESS;

    if (!ctx->session.greeting())
      return EXIT_BAD_GREETING;

    istream_input<eol::crlf, 1> in(ctx->session.in(), FLAGS_cmd_bfr_size,
                                   "session");

    if (!parse<RFC5321::grammar, RFC5321::action>(in, *ctx)) {
      return EXIT_SMTP_SYNTAX_ERROR;
    }
    else if (ctx->session.maxed_out()) {
      ctx->session.max_out();
      return EXIT_MAXED_OUT;
    }
    else if (ctx->session.timed_out()) {
      ctx->session.time_out();
      return EXIT_TIME_OUT;
    }
    // else {
    //   ctx->session.error("session end without QUIT command from client");
    // }
  }
  catch (std::runtime_error const& e) {
    LOG(WARNING) << e.what();
    return EXIT_EXCPETION;
  }
  catch (std::exception const& e) {
    LOG(WARNING) << e.what();
    return EXIT_EXCPETION;
  }
  catch (...) {
    LOG(WARNING) << "unknown exception";
    return EXIT_EXCPETION;
  }

  return EXIT_SUCCESS;
}

struct service {
  int fd = -1;

  socklen_t ctrl_addr_size = 0;
  union {
    struct sockaddr         addr;
    struct sockaddr_in      addr_in;
    struct sockaddr_in6     addr_in6;
    struct sockaddr_storage addr_storage;
  } ctrl;
  std::string ctrl_address;

  std::string host;
  std::string port;

  std::string canonname;
  int         family;
  int         socktype;
  int         protocol;
};

std::vector<service> services;

struct server {
  service* service_ptr = nullptr;

  socklen_t remote_addr_size = 0;
  union {
    struct sockaddr         addr;
    struct sockaddr_in      addr_in;
    struct sockaddr_in6     addr_in6;
    struct sockaddr_storage addr_storage;
  } remote;
  std::string remote_string;
};

std::unordered_map<pid_t, server> servers;

static constexpr uint64_t max_connections = 2;

struct counter_def {
  uint64_t max;
  time_t   window;
};

static constexpr counter_def rate_counters[]{
    {10, 60},             // per minute
    {100, 60 * 60},       // per hour
    {1000, 24 * 60 * 60}, // per day
};

struct counter {
  uint64_t count = 0;
  time_t   start = 0;
};

struct connection {
  uint64_t ncurrent = 0;
  uint64_t ntotal   = 0;
  uint64_t attempts = 0;
  uint64_t nerrors  = 0;
  counter  rates[std::size(rate_counters)];
  time_t   last_rejected = 0;
  time_t   tainted_at    = 0;
  bool     tainted       = false;
};

std::unordered_map<std::string, connection> connections;

int wait_any(int* wstat)
{
  pid_t r;

  do
    r = waitpid(-1, wstat, WNOHANG);
  while ((r == -1) && (errno == EINTR));

  return r;
}

void sigchild(int signum)
{
  pid_t pid;
  int   status;
  int   save_errno = errno;

  for (;;) {
    // LOG(INFO) << "sigchild, about to waitpid";
    google::FlushLogFiles(google::INFO);

    pid = wait_any(&status);
    // LOG(INFO) << "waitpid returned " << pid;

    if ((pid == -1) && (errno != ECHILD))
      LOG(INFO) << strerror(errno);

    // google::FlushLogFiles(google::INFO);

    if (pid <= 0)
      break;

    try {
      auto  srv        = servers.at(pid);
      auto& connection = connections[srv.remote_string];

      // srv.service_ptr
      if (WIFEXITED(status)) {
        auto exit_status = WEXITSTATUS(status);
        LOG(INFO) << "pid == " << pid << " status "
                  << exit_as_text(exit_status);
        if (exit_status != 0) {
          connection.nerrors++;
        }

        // Any of these cases taint the sender.
        switch (exit_status) {
        case EXIT_BAD_GREETING:   // Input before greeting, or dnsbl.
        case EXIT_BAD_IP_ADDRESS: // DNSBL
        case EXIT_BAD_LO:         // Claimed identity is blocked.
        case EXIT_BAD_MAIL_FROM:  // Sender blocked.
          connection.tainted    = true;
          connection.tainted_at = time(nullptr);
          break;
        }
      }
      else if (WIFSIGNALED(status)) {
        auto exit_signal = WTERMSIG(status);
        LOG(INFO) << "pid == " << pid << " signal " << exit_signal;
        connection.nerrors++; // signals count as errors
      }
      else {
        LOG(ERROR) << "pid == " << pid << ": not status or signal";
        connection.nerrors++; // whatever this is, counts as an error
      }

      connection.ncurrent--;
      connection.ntotal++;

      google::FlushLogFiles(google::INFO);

      servers.erase(pid);
    }
    catch (const std::out_of_range& ex) {
      LOG(ERROR) << "not watching pid == " << pid;
    }
  }
  errno = save_errno;
}

char const* fam_to_str(int fam)
{
  switch (fam) {
  case AF_INET: return "AF_INET";
  case AF_INET6: return "AF_INET6";
  }
  return "AF_?unknown?";
}

char const* typ_to_str(int typ)
{
  switch (typ) {
  case SOCK_STREAM: return "SOCK_STREAM";
  case SOCK_DGRAM: return "SOCK_DGRAM";
  }
  return "SOCK_?unknown?";
}

char const* pro_to_str(int pro)
{
  switch (pro) {
  case IPPROTO_IP: return "IPPROTO_IP";
  case IPPROTO_TCP: return "IPPROTO_TCP";
  case IPPROTO_UDP: return "IPPROTO_UDP";
  }
  return "IPPROTO_?unknown?";
}

void log_stats()
{
  auto constexpr bfr_sz = sizeof("2099-99-99T99:99:99Z");
  char time_buf[bfr_sz];

  for (auto const& [addr, conn] : connections) {
    std::string report;

    fmt::format_to(std::back_inserter(report),
                   "\n==== {:15} ===="
                   "\n  current: {}"
                   "\n    total: {}"
                   "\n attempts: {}"
                   "\n   errors: {}",
                   addr, conn.ncurrent, conn.ntotal, conn.attempts,
                   conn.nerrors);
    if (conn.tainted) {
      CHECK_EQ(strftime(time_buf, sizeof time_buf, "%FT%TZ",
                        gmtime(&conn.tainted_at)),
               sizeof(time_buf) - 1);
      fmt::format_to(std::back_inserter(report), "\n  tainted at {}", time_buf);
    }
    for (auto rate_num = 0uz; rate_num < std::size(conn.rates); ++rate_num) {
      CHECK_EQ(strftime(time_buf, sizeof time_buf, "%FT%TZ",
                        gmtime(&conn.rates[rate_num].start)),
               sizeof(time_buf) - 1);
      fmt::format_to(std::back_inserter(report),
                     "\n---- {} sec window ----"
                     "\n    count: {}"
                     "\n      max: {}"
                     "\n    since: {}",
                     rate_counters[rate_num].window, conn.rates[rate_num].count,
                     rate_counters[rate_num].max, time_buf);
    }
    fmt::format_to(std::back_inserter(report),
                   "\n==============================");
    LOG(INFO) << report;
  }
}

// Listen and accept client connections, then fork a session manager.

int server()
{
  // LOG(INFO) << "running server";

  struct sigaction sact{};
  PCHECK(sigemptyset(&sact.sa_mask) == 0);

  sact.sa_handler = sighup;
  PCHECK(sigaction(SIGHUP, &sact, nullptr) == 0);

  sact.sa_handler = sigquit;
  PCHECK(sigaction(SIGQUIT, &sact, nullptr) == 0);
  PCHECK(sigaction(SIGINT, &sact, nullptr) == 0);

  sact.sa_handler = sigchild;
  PCHECK(sigaction(SIGCHLD, &sact, nullptr) == 0);

  auto const host = FLAGS_bind.c_str();
  auto const port = FLAGS_service.c_str();

  fd_set allsock;
  FD_ZERO(&allsock);
  int maxsock = -1;

  struct addrinfo hints{};
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_PASSIVE | AI_CANONNAME;

  struct addrinfo* result = nullptr;
  int              s      = getaddrinfo(host, port, &hints, &result);
  CHECK_EQ(s, 0) << "getaddrinfo: " << gai_strerror(s);

  for (auto rp = result; rp != nullptr; rp = rp->ai_next) {
    services.emplace_back();
    services.back().host      = host;                 // same for all
    services.back().port      = port;                 // same for all
    services.back().canonname = result->ai_canonname; // grab from 1st result
    services.back().family    = rp->ai_family;
    services.back().socktype  = rp->ai_socktype;
    services.back().protocol  = rp->ai_protocol;

    memcpy(&services.back().ctrl.addr, rp->ai_addr, rp->ai_addrlen);
    services.back().ctrl_addr_size = rp->ai_addrlen;

    CHECK_EQ(rp->ai_socktype, SOCK_STREAM);
    CHECK_EQ(rp->ai_socktype, hints.ai_socktype);

    switch (rp->ai_addrlen) {
    case sizeof(struct sockaddr_in): {
      char str[INET_ADDRSTRLEN]{};
      CHECK_EQ(rp->ai_family, AF_INET);
      struct sockaddr_in* sin =
          reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
      PCHECK(inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)));
      services.back().ctrl_address = str;
      break;
    }
    case sizeof(struct sockaddr_in6): {
      char str[INET6_ADDRSTRLEN]{};
      CHECK_EQ(rp->ai_family, AF_INET6);
      struct sockaddr_in6* sin6 =
          reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
      PCHECK(inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)));
      services.back().ctrl_address = str;
      break;
    }
    default: LOG(FATAL) << "Unknown addrlen " << rp->ai_addrlen;
    }

    services.back().fd =
        socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

    PCHECK(services.back().fd) << "Can't open server listening socket";

    int on = 1;
    if (FLAGS_soc_debug)
      PCHECK(setsockopt(services.back().fd, SOL_SOCKET, SO_DEBUG, &on,
                        sizeof(on)) >= 0);
    PCHECK(setsockopt(services.back().fd, SOL_SOCKET, SO_REUSEADDR, &on,
                      sizeof(on)) >= 0);

    int r = bind(services.back().fd, &services.back().ctrl.addr,
                 services.back().ctrl_addr_size);
    PCHECK(r == 0) << "bind failed fd=" << services.back().fd << " "
                   << services.back().canonname << " "
                   << services.back().ctrl_address;

    PCHECK(listen(services.back().fd, 10) == 0);

    FD_SET(services.back().fd, &allsock);
    LOG(INFO) << "listening (fd=" << services.back().fd << ") on "
              << services.back().canonname << " ["
              << services.back().ctrl_address << "]:" << services.back().port;

    maxsock = std::max(services.back().fd, maxsock);
  }
  freeaddrinfo(result);

  if (maxsock < 0) {
    LOG(INFO) << "no sockets to listen on";
    return 0;
  }

  while (!sig_quit) {
    // LOG(INFO) << "server waiting for connections…";
    // google::FlushLogFiles(google::INFO);

    if (sig_hup) {
      log_stats();
      sig_hup = false;
    }

    auto readable     = allsock;
    auto ready_fd_cnt = select(maxsock + 1, &readable, NULL, NULL, NULL);

    if (ready_fd_cnt < 0) {
      if (errno != EINTR) {
        auto const errmsg = std::strerror(errno);
        LOG(ERROR) << "select: " << errmsg;
        (void)sleep(1);
      }
      continue;
    }
    // LOG(INFO) << "select() returned " << ready_fd_cnt << " ready fds";

    for (auto service : services) {
      if (service.fd == -1 || !FD_ISSET(service.fd, &readable))
        continue;

      int accepted_fd = -1;

      struct server srv;
      srv.service_ptr = &service;

      srv.remote_addr_size = sizeof(srv.remote.addr_storage);
      accepted_fd = accept(service.fd, &srv.remote.addr, &srv.remote_addr_size);
      if (accepted_fd < 0) {
        PCHECK(errno == EINTR) << "accept for " << service.fd;
        continue;
      }

      switch (srv.remote_addr_size) {
      case sizeof(struct sockaddr_in): {
        char str[INET_ADDRSTRLEN];
        CHECK_EQ(service.family, AF_INET);
        struct sockaddr_in* sin =
            reinterpret_cast<struct sockaddr_in*>(&srv.remote.addr);
        PCHECK(inet_ntop(service.family, &sin->sin_addr, str, sizeof(str)));
        srv.remote_string = str;
        break;
      }
      case sizeof(struct sockaddr_in6): {
        char str[INET6_ADDRSTRLEN];
        CHECK_EQ(service.family, AF_INET6);
        struct sockaddr_in6* sin6 =
            reinterpret_cast<struct sockaddr_in6*>(&srv.remote.addr);
        PCHECK(inet_ntop(service.family, &sin6->sin6_addr, str, sizeof(str)));
        srv.remote_string = str;
        break;
      }
      default: LOG(FATAL) << "Unknown addrlen " << srv.remote_addr_size;
      }

      auto& connection = connections[srv.remote_string];

      auto const now = time(nullptr);

      ++connection.attempts;

      if (connection.tainted) {
        connection.last_rejected = time(nullptr);
        char const msg[]         = "550 5.7.1 sender blocked\r\n";
        (void)write(accepted_fd, msg, sizeof(msg));
        PCHECK(close(accepted_fd) == 0);
        LOG(INFO) << "tainted sender " << srv.remote_string;
        continue;
      }

      bool limited = false;
      for (auto rate_num = 0uz; rate_num < std::size(connection.rates);
           ++rate_num) {
        auto& rate = connection.rates[rate_num];
        if ((rate.start == time_t{0}) ||
            (rate.start + rate_counters[rate_num].window < now)) {
          rate.count = 1;
          rate.start = now;
        }
        else if (!limited && ++rate.count >= rate_counters[rate_num].max) {
          connection.last_rejected = now;
          std::string msg =
              fmt::format("Too many connections {} within {} seconds.",
                          rate.count, rate_counters[rate_num].window);
          std::string error_str =
              fmt::format("421 4.3.0 {} Try again later.\r\n", msg);
          (void)write(accepted_fd, error_str.data(), error_str.size());
          PCHECK(close(accepted_fd) == 0);
          LOG(INFO) << msg;
          --rate.count;
          limited = true;
          break;
        }
      }
      if (limited)
        continue;

      if (++connection.ncurrent >= max_connections) {
        connection.ncurrent--;
        connection.last_rejected = time(nullptr);
        char const too_many[] =
            "421 4.3.0 Too many concurrent connections, try again later.\r\n";
        (void)write(accepted_fd, too_many, sizeof(too_many));
        PCHECK(close(accepted_fd) == 0);
        LOG(INFO) << "too many concurrent connections from "
                  << srv.remote_string;
        continue;
      }

      // LOG(INFO) << "about to fork";
      // google::FlushLogFiles(google::INFO);

      int pid = fork();

      if (pid < 0) { // fork error
        LOG(FATAL) << "fork: " << std::strerror(errno);
      }

      if (pid > 0) { // parent
        servers[pid] = srv;
        LOG(INFO) << fmt::format("pid == {} for {:15}", pid, srv.remote_string);
        PCHECK(close(accepted_fd) == 0); // We passed this to our child.
        continue;                        // Check next srv…
      }

      CHECK_EQ(pid, 0); // child
      PCHECK(setsid() != -1);

      // Drop root
      uid_t ruid, euid, suid;
      PCHECK(getresuid(&ruid, &euid, &suid) == 0);

      // gid_t rgid, egid, sgid;
      // PCHECK(getresgid(&rgid, &egid, &sgid) == 0);

      if (ruid == 0) {
        // run by root, ensure groups vector gets trashed
        gid_t gid = getgid();
        setgroups(1, &gid);
      }

      char const* user = getenv("USER");
      if (user == nullptr)
        user = "gene";
      struct passwd* pwd = getpwnam(user);
      PCHECK(pwd != nullptr) << "no such user " << user;

      if (pwd->pw_uid != euid) {
        // LOG(INFO) << "switching to user " << pwd->pw_name
        // << " uid == " << pwd->pw_uid << " gid == " << pwd->pw_gid;

        PCHECK(setgid(pwd->pw_gid) == 0) << "setgid(" << pwd->pw_gid << ")";
        PCHECK(setuid(pwd->pw_uid) == 0) << "setuid(" << pwd->pw_uid << ")";
      }

      // We can leave STDERR_FILENO alone.
      if (accepted_fd != STDIN_FILENO) {
        PCHECK(dup2(accepted_fd, STDIN_FILENO) == STDIN_FILENO);
      }
      PCHECK(dup2(STDIN_FILENO, STDOUT_FILENO) == STDOUT_FILENO);

      for (auto service : services) {
        PCHECK(close(service.fd) == 0);
        service.fd = -1;
      }

      try {
        return session();
      }
      catch (std::exception const& ex) {
        LOG(FATAL) << ex.what();
      }
      catch (...) {
        LOG(FATAL) << "Unknown excpetion";
      }
    }
  }

  LOG(INFO) << "quitting";

  try {
    auto const config_path = osutil::get_config_dir();
  }
  catch (...) {
  }

  for (auto service : services) {
    PCHECK(close(service.fd) == 0);
    service.fd = -1;
  }

  log_stats();

  for (auto n = 0; servers.size(); ++n) {
    LOG(WARNING) << (n ? "still " : "") << "waiting for " << servers.size()
                 << " running servers";

    (void)sleep(n & 3);

    if (n > 5) {
      for (auto const& [pid, srv] : servers) {
        LOG(WARNING) << "killing pid " << pid;
        kill(pid, SIGKILL);
      }
    }
  }

  return 0;
}

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);

  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  auto const log_dir(getenv("GOOGLE_LOG_DIR"));
  if (log_dir) {
    error_code ec;
    fs::create_directories(log_dir, ec);
  }

  google::InitGoogleLogging(argv[0]);

  // Don't wait for STARTTLS to fail if no cert.
  auto const config_path = osutil::get_config_dir();
  auto const certs = osutil::list_directory(config_path, Config::cert_fn_re);
  CHECK_GE(certs.size(), 1) << "no certs found";

  if (FLAGS_server)
    return server();
  else
    return session();
}

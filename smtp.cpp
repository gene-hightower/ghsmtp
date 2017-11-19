#include <gflags/gflags.h>
namespace gflags {
};

#include <fstream>

#include "Session.hpp"
#include "esc.hpp"

#include <cstdlib>
#include <memory>

#include <signal.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

namespace Config {
constexpr std::streamsize bfr_size = 4 * 1024;
constexpr std::streamsize max_hdr_size = 16 * 1024;
constexpr std::streamsize max_xfer_size = 64 * 1024;
} // namespace Config

namespace RFC5321 {

struct Ctx {
  Ctx(std::function<void(void)> read_hook = []() {})
    : session(read_hook)
  {
  }
  Session session;

  std::unique_ptr<Message> msg;

  std::string hdr;

  std::string mb_loc;
  std::string mb_dom;

  std::pair<std::string, std::string> param;
  std::unordered_map<std::string, std::string> parameters;

  size_t chunk_size;
  bool chunk_first{true};
  bool chunk_last{false};
  bool bdat_error{false};

  bool hdr_end{false};
  bool hdr_parsed{false};

  void bdat_rset()
  {
    chunk_first = true;
    chunk_last = false;
    bdat_error = false;
    hdr_end = false;
    hdr_parsed = false;
  }

  void new_msg()
  {
    msg = std::make_unique<Message>();
    hdr.clear();
    hdr_end = false;
    hdr_parsed = false;
    session.data_msg(*msg);
  }

  bool hdr_parse()
  {
    if (hdr_parsed)
      return true;

    if (!hdr_end) {
      LOG(ERROR) << "may not have whole header";
      return false;
    }
    if (hdr.size() > Config::max_hdr_size) {
      LOG(ERROR) << "header size too large";
      return false;
    }

    // parse header

    return hdr_parsed = true;
  }
};

struct no_last_dash { // not used now...
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

struct u_ldh_str : plus<sor<ALPHA, DIGIT, UTF8_non_ascii, dash>> {
  // verify last char is a U_Let_dig
};

struct u_label : seq<u_let_dig, opt<u_ldh_str>> {};

struct let_dig : sor<ALPHA, DIGIT> {};

struct ldh_str : plus<sor<ALPHA, DIGIT, dash>> {
  // verify last char is a U_Let_dig
};

struct label : seq<let_dig, opt<ldh_str>> {};

struct sub_domain : sor<label, u_label> {};

struct domain : list<sub_domain, dot> {};

struct dec_octet : sor<one<'0'>,
                       rep_min_max<1, 2, DIGIT>,
                       seq<one<'1'>, DIGIT, DIGIT>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<string<'2','5'>, range<'0','5'>>> {};

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

struct IPv6_address_literal : seq<TAOCPP_PEGTL_ISTRING("IPv6:"), IPv6address> {};

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

struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, UTF8_non_ascii> {};

struct graphic : range<32, 126> {};

struct quoted_pairSMTP : seq<one<'\\'>, graphic> {};

struct qcontentSMTP : sor<qtextSMTP, quoted_pairSMTP> {};

struct quoted_string : seq<one<'"'>, star<qcontentSMTP>, one<'"'>> {};

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
                   UTF8_non_ascii> {};

struct atom : plus<atext> {};

struct dot_string : list<atom, dot> {};

struct local_part : sor<dot_string, quoted_string> {};

struct non_local_part : sor<domain, address_literal> {};

struct mailbox : seq<local_part, one<'@'>, non_local_part> {};

struct path : seq<one<'<'>, seq<opt<seq<a_d_l, colon>>, mailbox, one<'>'>>> {};

struct bounce_path : TAOCPP_PEGTL_ISTRING("<>") {};

struct reverse_path : sor<path, bounce_path> {};

struct magic_postmaster : TAOCPP_PEGTL_ISTRING("<Postmaster>") {};

struct forward_path : sor<path, magic_postmaster> {};

struct esmtp_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash>>> {};

struct esmtp_value : plus<sor<range<33, 60>, range<62, 126>, UTF8_non_ascii>> {};

struct esmtp_param : seq<esmtp_keyword, opt<seq<one<'='>, esmtp_value>>> {};

struct mail_parameters : list<esmtp_param, SP> {};

struct rcpt_parameters : list<esmtp_param, SP> {};

struct string : sor<quoted_string, atom> {};

struct helo : seq<TAOCPP_PEGTL_ISTRING("HELO"),
                  SP, domain, CRLF> {};

struct ehlo : seq<TAOCPP_PEGTL_ISTRING("EHLO"),
                  SP,
                  sor<domain, address_literal>,
                  CRLF> {};

struct mail_from : seq<TAOCPP_PEGTL_ISTRING("MAIL"),
                       TAOCPP_PEGTL_ISTRING(" FROM:"),
                       opt<SP>, // obsolete in RFC5321, but kosher in RFC821
                       reverse_path,
                       opt<seq<SP, mail_parameters>>,
                       CRLF> {};

struct rcpt_to : seq<TAOCPP_PEGTL_ISTRING("RCPT"),
                     TAOCPP_PEGTL_ISTRING(" TO:"),
                     opt<SP>, // obsolete in RFC5321, but kosher in RFC821
                     forward_path,
                     opt<seq<SP, rcpt_parameters>>,
                     CRLF> {};

struct chunk_size : plus<DIGIT> {};

struct end_marker : TAOCPP_PEGTL_ISTRING(" LAST") {};

struct bdat : seq<TAOCPP_PEGTL_ISTRING("BDAT"), SP, chunk_size, CRLF> {};

struct bdat_last
    : seq<TAOCPP_PEGTL_ISTRING("BDAT"), SP, chunk_size, end_marker, CRLF> {};

struct data : seq<TAOCPP_PEGTL_ISTRING("DATA"), CRLF> {};

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

struct rset : seq<TAOCPP_PEGTL_ISTRING("RSET"), CRLF> {};

struct noop : seq<TAOCPP_PEGTL_ISTRING("NOOP"), opt<seq<SP, string>>, CRLF> {};

struct vrfy : seq<TAOCPP_PEGTL_ISTRING("VRFY"), opt<seq<SP, string>>, CRLF> {};

struct help : seq<TAOCPP_PEGTL_ISTRING("HELP"), opt<seq<SP, string>>, CRLF> {};

struct starttls
    : seq<TAOCPP_PEGTL_ISTRING("STAR"), TAOCPP_PEGTL_ISTRING("TTLS"), CRLF> {};

struct quit : seq<TAOCPP_PEGTL_ISTRING("QUIT"), CRLF> {};

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
    if (ctx.mb_loc.length() > 255) {
      LOG(WARNING) << "domain name or number too long " << ctx.mb_dom;
    }
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
  static void apply(Input const& in, Ctx& ctx)
  {
    auto beg = in.begin() + 5; // +5 for the length of "HELO "
    auto end = in.end() - 2;   // -2 for the CRLF
    ctx.session.helo(std::string_view(beg, end - beg));
    ctx.bdat_rset();
  }
};

template <>
struct action<ehlo> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto beg = in.begin() + 5; // +5 for the length of "EHLO "
    auto end = in.end() - 2;   // -2 for the CRLF
    ctx.session.ehlo(std::string_view(beg, end - beg));
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
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.chunk_size = std::strtoul(in.string().c_str(), nullptr, 10);
  }
};

template <>
struct action<end_marker> {
  static void apply0(Ctx& ctx) { ctx.chunk_last = true; }
};

void bdat_act(Ctx& ctx)
{
  if (ctx.chunk_first) {
    ctx.chunk_first = false;

    if (!ctx.session.bdat_start()) {
      // no need to ctx.msg.reset() when bdat_start fails
      ctx.bdat_error = true;
      LOG(ERROR) << "bdat_start() returned error!";

      // seek over BDAT data
      auto pos = ctx.session.in().tellg();
      pos += ctx.chunk_size;
      ctx.session.in().seekg(pos, ctx.session.in().beg);

      return;
    }

    ctx.new_msg();
  }

  if (ctx.bdat_error) { // If we've already failed...
    LOG(ERROR) << "BDAT continuing data error, skiping " << ctx.chunk_size
               << " octets";

    ctx.session.bdat_error(*ctx.msg);

    // seek over BDAT data
    auto pos = ctx.session.in().tellg();
    pos += ctx.chunk_size;
    ctx.session.in().seekg(pos, ctx.session.in().beg);

    return;
  }
  else if (ctx.chunk_size > ctx.msg->size_left()) {
    LOG(ERROR) << "BDAT size error, skiping " << ctx.chunk_size << " octets";

    ctx.session.data_size_error(*ctx.msg);
    ctx.bdat_error = true;
    ctx.msg.reset();

    // seek over BDAT data
    auto pos = ctx.session.in().tellg();
    pos += ctx.chunk_size;
    ctx.session.in().seekg(pos, ctx.session.in().beg);

    return;
  }

  // First off, for every BDAT, we /must/ read the data, if there is any.
  std::string bfr;

  std::streamsize to_xfer = ctx.chunk_size;

  while (to_xfer) {
    auto xfer_sz = std::min(to_xfer, Config::max_xfer_size);
    bfr.resize(xfer_sz);

    ctx.session.in().read(&bfr[0], xfer_sz);
    CHECK(ctx.session.in()) << "read failed";

    if (!ctx.hdr_end) {
      auto e = bfr.find("\r\n\r\n");
      if (ctx.hdr.size() < Config::max_hdr_size) {
        ctx.hdr += bfr.substr(0, e);
        if (e == std::string::npos) {
          LOG(WARNING) << "may not have all headers in this chunk";
        }
        else {
          ctx.hdr.append("\r\n");
          ctx.hdr_end = true;
        }
      }
    }

    ctx.msg->write(&bfr[0], xfer_sz);

    to_xfer -= xfer_sz;
  }

  if (ctx.msg->size_error()) {
    LOG(ERROR) << "message size error after " << ctx.msg->size() << " octets";
    ctx.session.data_size_error(*ctx.msg);
    ctx.bdat_error = true;
    ctx.msg.reset();
    return;
  }

  if (ctx.chunk_last) {
    if (!ctx.hdr_end) {
      LOG(WARNING) << "may not have all headers in this email";
    }
    ctx.session.bdat_msg_last(*ctx.msg, ctx.chunk_size);
    ctx.msg.reset();
    ctx.chunk_first = true;
  }
  else {
    ctx.session.bdat_msg(*ctx.msg, ctx.chunk_size);
  }
}

template <>
struct action<bdat> {
  static void apply0(Ctx& ctx) { bdat_act(ctx); }
};

template <>
struct action<bdat_last> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    bdat_act(ctx);
    ctx.bdat_error = true; // to make next BDAT fail.
  }
};

template <>
struct data_action<data_end> {
  static void apply0(Ctx& ctx)
  {
    if (ctx.msg) {
      if (ctx.msg->size_error()) {
        ctx.session.data_size_error(*ctx.msg);
        ctx.msg.reset();
      }
      else {
        if (!ctx.hdr_end) {
          LOG(WARNING) << "may not have all headers in this email";
        }
        ctx.session.data_msg_done(*ctx.msg);
        ctx.msg.reset();
      }
    }
  }
};

template <>
struct data_action<data_blank> {
  static void apply0(Ctx& ctx)
  {
    constexpr char CRLF[]{'\r', '\n'};
    if (ctx.msg) {
      ctx.msg->write(CRLF, sizeof(CRLF));
    }
    ctx.hdr.append(CRLF, sizeof(CRLF));
    ctx.hdr_end = true;
  }
};

template <>
struct data_action<data_plain> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    size_t len = in.end() - in.begin();
    if (ctx.msg) {
      ctx.msg->write(in.begin(), len);
    }
    if (!ctx.hdr_end) {
      if (ctx.hdr.size() < Config::max_hdr_size) {
        ctx.hdr.append(in.begin(), len);
      }
    }
  }
};

template <>
struct data_action<data_dot> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    size_t len = in.end() - in.begin() - 1;
    if (ctx.msg) {
      ctx.msg->write(in.begin() + 1, len);
    }
    if (!ctx.hdr_end) {
      LOG(WARNING) << "suspicious encoding used in header";
      if (ctx.hdr.size() < Config::max_hdr_size) {
        auto hlen = std::min(len, Config::max_hdr_size - ctx.hdr.size());
        std::copy_n(in.begin() + 1, hlen, std::back_inserter(ctx.hdr));
      }
    }
  }
};

template <>
struct data_action<not_data_end> {
  static void apply0(Ctx& ctx) { ctx.session.bare_lf(); }
};

template <>
struct data_action<anything_else> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    LOG(WARNING) << "garbage in data stream: \"" << esc(in.string()) << "\"";
    size_t len = in.end() - in.begin();
    CHECK(len);
    if (ctx.msg) {
      ctx.msg->write(in.begin(), len);
    }
    if (!ctx.hdr_end) {
      if (ctx.hdr.size() < Config::max_hdr_size) {
        ctx.hdr.append(in.begin(), len);
      }
    }
  }
};

template <>
struct action<data> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    if (ctx.session.data_start()) {
      ctx.new_msg();

      istream_input<eol::crlf> data_in(ctx.session.in(), Config::bfr_size,
                                       "data");
      try {
        if (!parse_nested<RFC5321::data_grammar, RFC5321::data_action>(
                in, data_in, ctx)) {
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
  static void apply0(Ctx& ctx)
  {
    ctx.session.rset();
    ctx.bdat_rset();
  }
};

template <typename Input>
std::string_view get_string(Input const& in)
{
  auto beg = in.begin() + 4;
  auto len = in.end() - beg;
  auto str = std::string_view(beg, len);
  if (str.front() == ' ')
    str.remove_prefix(1);
  return str;
}

template <>
struct action<noop> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto str = get_string(in);
    ctx.session.noop(str);
  }
};

template <>
struct action<vrfy> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto str = get_string(in);
    ctx.session.vrfy(str);
  }
};

template <>
struct action<help> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    auto str = get_string(in);
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
} // namespace RFC5321

void timeout(int signum)
{
  const char errmsg[] = "421 4.4.2 time-out\r\n";
  write(STDOUT_FILENO, errmsg, sizeof errmsg - 1);
  _exit(1);
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
  sact.sa_flags = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);
  alarm(2 * 60); // initial alarm

  close(2); // hackage to stop glog from spewing

  google::InitGoogleLogging(argv[0]);

  // Don't wait for STARTTLS to fail if no cert.
  CHECK(fs::exists(TLS::cert_path)) << "can't find cert file";

  std::unique_ptr<RFC5321::Ctx> ctx;
  auto read_hook = [&ctx]() { ctx->session.flush(); };
  ctx = std::make_unique<RFC5321::Ctx>(read_hook);

  ctx->session.greeting();

  istream_input<eol::crlf> in(ctx->session.in(), Config::bfr_size, "session");

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
  else {
    ctx->session.error("syntax error from parser");
  }

  return ret;
}

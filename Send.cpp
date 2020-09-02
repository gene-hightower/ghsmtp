#include "Send.hpp"

#include <random>

#include "IP4.hpp"
#include "IP6.hpp"
#include "SRS.hpp"
#include "imemstream.hpp"
#include "rewrite.hpp"

#include <gflags/gflags.h>

// This needs to be at least the length of each string it's trying to match.
DEFINE_uint64(pbfr_size, 4 * 1024, "parser buffer size");

DEFINE_bool(use_esmtp, true, "use ESMTP (EHLO)");

DEFINE_string(local_address, "", "local address to bind");

#include <boost/algorithm/string/case_conv.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

using std::begin;
using std::end;

// clang-format off

namespace chars {
struct tail : range<'\x80', '\xBF'> {};

struct ch_1 : range<'\x00', '\x7F'> {};

struct ch_2 : seq<range<'\xC2', '\xDF'>, tail> {};

struct ch_3 : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, tail>,
                  seq<range<'\xE1', '\xEC'>, rep<2, tail>>,
                  seq<one<'\xED'>, range<'\x80', '\x9F'>, tail>,
                  seq<range<'\xEE', '\xEF'>, rep<2, tail>>> {};

struct ch_4 : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, tail>>,
                  seq<range<'\xF1', '\xF3'>, rep<3, tail>>,
                  seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, tail>>> {};

struct u8char : sor<ch_1, ch_2, ch_3, ch_4> {};

struct non_ascii : sor<ch_2, ch_3, ch_4> {};

struct ascii_only : seq<star<ch_1>, eof> {};

struct utf8_only : seq<star<u8char>, eof> {};
}

namespace SMTP {

// clang-format off

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, chars::non_ascii> {};

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


struct qtextSMTP : sor<ranges<32, 33, 35, 91, 93, 126>, chars::non_ascii> {};
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
                   chars::non_ascii> {};
struct atom : plus<atext> {};
struct dot_string : list<atom, dot> {};
struct quoted_string : seq<one<'"'>, star<qcontentSMTP>, one<'"'>> {};
struct local_part : sor<dot_string, quoted_string> {};
struct non_local_part : sor<domain, address_literal> {};
struct mailbox : seq<local_part, one<'@'>, non_local_part> {};

struct at_domain : seq<one<'@'>, domain> {};

struct a_d_l : list<at_domain, one<','>> {};

struct path : seq<opt<seq<a_d_l, colon>>, mailbox> {};

struct path_only : seq<path, eof> {};

// textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

// Although not explicit in the grammar of RFC-6531, in practice UTF-8
// is used in the replys.

// struct textstring : plus<sor<one<9>, range<32, 126>>> {};

  struct textstring : plus<sor<one<9>, range<32, 126>, chars::non_ascii>> {};

struct server_id : sor<domain, address_literal> {};

// Greeting       = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF )
//                  /
//                  ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
//                 *( "220-" [ textstring ] CRLF )
//                    "220 " [ textstring ] CRLF )

struct greeting_ok
: sor<seq<TAO_PEGTL_ISTRING("220 "), server_id, opt<textstring>, CRLF>,
      seq<TAO_PEGTL_ISTRING("220-"), server_id, opt<textstring>, CRLF,
 star<seq<TAO_PEGTL_ISTRING("220-"), opt<textstring>, CRLF>>,
      seq<TAO_PEGTL_ISTRING("220 "), opt<textstring>, CRLF>>> {};

// Reply-code     = %x32-35 %x30-35 %x30-39

struct reply_code
: seq<range<0x32, 0x35>, range<0x30, 0x35>, range<0x30, 0x39>> {};

// Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
//                     Reply-code  [ SP textstring ] CRLF

struct reply_lines
: seq<star<seq<reply_code, one<'-'>, opt<textstring>, CRLF>>,
           seq<reply_code, opt<seq<SP, textstring>>, CRLF>> {};

struct greeting
  : sor<greeting_ok, reply_lines> {};

// ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
//                    ; string of any characters other than CR or LF

struct ehlo_greet : plus<ranges<0, 9, 11, 12, 14, 127>> {};

// ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
//                  ; additional syntax of ehlo-params depends on
//                  ; ehlo-keyword

// The '.' we also allow in ehlo-keyword since it has been seen in the
// wild at least at 263.net.

struct ehlo_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash, dot>>> {};

// ehlo-param     = 1*(%d33-126)
//                  ; any CHAR excluding <SP> and all
//                  ; control characters (US-ASCII 0-31 and 127
//                  ; inclusive)

struct ehlo_param : plus<range<33, 126>> {};

// ehlo-line      = ehlo-keyword *( SP ehlo-param )

// The AUTH= thing is so common with some servers (postfix) that I
// guess we have to accept it.

struct ehlo_line
    : seq<ehlo_keyword, star<seq<sor<SP,one<'='>>, ehlo_param>>> {};

// ehlo-ok-rsp    = ( "250 " Domain [ SP ehlo-greet ] CRLF )
//                  /
//                  ( "250-" Domain [ SP ehlo-greet ] CRLF
//                 *( "250-" ehlo-line CRLF )
//                    "250 " ehlo-line CRLF )

// The last line having the optional ehlo_line is not strictly correct.
// Was added to work with postfix/src/smtpstone/smtp-sink.c.

struct ehlo_ok_rsp
: sor<seq<TAO_PEGTL_ISTRING("250 "), server_id, opt<ehlo_greet>, CRLF>,

      seq<TAO_PEGTL_ISTRING("250-"), server_id, opt<ehlo_greet>, CRLF,
 star<seq<TAO_PEGTL_ISTRING("250-"), ehlo_line, CRLF>>,
      seq<TAO_PEGTL_ISTRING("250 "), opt<ehlo_line>, CRLF>>
      > {};

struct ehlo_rsp
  : sor<ehlo_ok_rsp, reply_lines> {};

struct helo_ok_rsp
  : seq<TAO_PEGTL_ISTRING("250 "), server_id, opt<ehlo_greet>, CRLF> {};

struct auth_login_username
    : seq<TAO_PEGTL_STRING("334 VXNlcm5hbWU6"), CRLF> {};

struct auth_login_password
    : seq<TAO_PEGTL_STRING("334 UGFzc3dvcmQ6"), CRLF> {};

// clang-format on

template <typename Rule>
struct inaction : nothing<Rule> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<server_id> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.server_id = in.string();
  }
};

template <>
struct action<local_part> {
  template <typename Input>
  static void apply(Input const& in, Mailbox& mbx)
  {
    mbx.set_local(in.string());
  }
};

template <>
struct action<non_local_part> {
  template <typename Input>
  static void apply(Input const& in, Mailbox& mbx)
  {
    mbx.set_domain(in.string());
  }
};

template <>
struct action<greeting_ok> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.greeting_ok = true;
    imemstream  stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << "S: " << line;
    }
  }
};

template <>
struct action<ehlo_ok_rsp> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.ehlo_ok = true;
    imemstream  stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << "S: " << line;
    }
  }
};

template <>
struct action<ehlo_keyword> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.ehlo_keyword = in.string();
    boost::to_upper(conn.ehlo_keyword);
  }
};

template <>
struct action<ehlo_param> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.ehlo_param.push_back(in.string());
  }
};

template <>
struct action<ehlo_line> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.ehlo_params.emplace(std::move(conn.ehlo_keyword),
                             std::move(conn.ehlo_param));
  }
};

template <>
struct action<reply_lines> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    imemstream  stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << "S: " << line;
    }
  }
};

template <>
struct action<reply_code> {
  template <typename Input>
  static void apply(Input const& in, Connection& conn)
  {
    conn.reply_code = in.string();
  }
};
} // namespace SMTP

namespace {
bool is_localhost(DNS::RR const& rr)
{
  if (std::holds_alternative<DNS::RR_MX>(rr)) {
    if (iequal(std::get<DNS::RR_MX>(rr).exchange(), "localhost"))
      return true;
  }
  return false;
}

std::vector<Domain> get_mxs(DNS::Resolver& res, Domain const& domain)
{
  auto mxs{std::vector<Domain>{}};

  // Non-local part is an address literal.
  if (domain.is_address_literal()) {
    mxs.emplace_back(domain);
    return mxs;
  }

  // RFC 5321 section 5.1 "Locating the Target Host"

  // “The lookup first attempts to locate an MX record associated with
  //  the name.  If a CNAME record is found, the resulting name is
  //  processed as if it were the initial name.”

  // Our (full) resolver will traverse any CNAMEs for us and return
  // the CNAME and MX records all together.

  auto const& dom = domain.ascii();

  auto q{DNS::Query{res, DNS::RR_type::MX, dom}};
  auto mx_recs{q.get_records()};

  mx_recs.erase(std::remove_if(begin(mx_recs), end(mx_recs), is_localhost),
                end(mx_recs));

  auto const nmx
      = std::count_if(begin(mx_recs), end(mx_recs), [](auto const& rr) {
          return std::holds_alternative<DNS::RR_MX>(rr);
        });

  if (nmx == 1) {
    for (auto const& mx : mx_recs) {
      if (std::holds_alternative<DNS::RR_MX>(mx)) {
        // RFC 7505 null MX record
        if ((std::get<DNS::RR_MX>(mx).preference() == 0)
            && (std::get<DNS::RR_MX>(mx).exchange().empty()
                || (std::get<DNS::RR_MX>(mx).exchange() == "."))) {
          LOG(WARNING) << "domain " << dom << " does not accept mail";
          return mxs;
        }
      }
    }
  }

  if (nmx == 0) {
    // domain must have address record
    mxs.emplace_back(dom);
    return mxs;
  }

  // […] then the sender-SMTP MUST randomize them to spread the load
  // across multiple mail exchangers for a specific organization.
  std::shuffle(begin(mx_recs), end(mx_recs), std::random_device());
  std::sort(begin(mx_recs), end(mx_recs), [](auto const& a, auto const& b) {
    if (std::holds_alternative<DNS::RR_MX>(a)
        && std::holds_alternative<DNS::RR_MX>(b)) {
      return std::get<DNS::RR_MX>(a).preference()
             < std::get<DNS::RR_MX>(b).preference();
    }
    return false;
  });

  LOG(INFO) << "MXs for " << domain << " are:";
  for (auto const& mx : mx_recs) {
    if (std::holds_alternative<DNS::RR_MX>(mx)) {
      mxs.emplace_back(std::get<DNS::RR_MX>(mx).exchange());
      LOG(INFO) << std::setfill(' ') << std::setw(3)
                << std::get<DNS::RR_MX>(mx).preference() << " "
                << std::get<DNS::RR_MX>(mx).exchange();
    }
  }

  return mxs;
}

int conn(DNS::Resolver& res, Domain const& node, uint16_t port)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  PCHECK(fd >= 0) << "socket() failed";

  if (!FLAGS_local_address.empty()) {
    auto loc{sockaddr_in{}};
    loc.sin_family = AF_INET;
    if (1
        != inet_pton(AF_INET, FLAGS_local_address.c_str(),
                     reinterpret_cast<void*>(&loc.sin_addr))) {
      LOG(FATAL) << "can't interpret " << FLAGS_local_address
                 << " as IPv4 address";
    }
    PCHECK(0 == bind(fd, reinterpret_cast<sockaddr*>(&loc), sizeof(loc)));
  }

  auto addrs{std::vector<std::string>{}};
  if (node.is_address_literal()) {
    if (IP4::is_address(node.ascii())) {
      addrs.push_back(node.ascii());
    }
    if (IP4::is_address_literal(node.ascii())) {
      auto const addr = IP4::as_address(node.ascii());
      addrs.push_back(std::string(addr.data(), addr.length()));
    }
  }
  else {
    addrs = res.get_strings(DNS::RR_type::A, node.ascii());
  }
  for (auto addr : addrs) {
    auto in4{sockaddr_in{}};
    in4.sin_family = AF_INET;
    in4.sin_port   = htons(port);
    CHECK_EQ(inet_pton(AF_INET, addr.c_str(),
                       reinterpret_cast<void*>(&in4.sin_addr)),
             1);
    if (connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4))) {
      PLOG(WARNING) << "connect failed " << addr << ":" << port;
      continue;
    }

    // LOG(INFO) << fd << " connected to " << addr << ":" << port;
    return fd;
  }

  close(fd);
  return -1;
}

std::optional<std::unique_ptr<SMTP::Connection>>
open_session(DNS::Resolver& res, fs::path config_path, Domain sender, Domain mx)
{
  int fd = conn(res, mx, 225);
  if (fd == -1) {
    LOG(WARNING) << mx << " no connection";
    return {};
  }

  // Listen for greeting

  auto constexpr read_hook{[]() {}};
  auto conn = std::make_unique<SMTP::Connection>(fd, fd, read_hook);

  auto in = istream_input<eol::crlf, 1>{conn->sock.in(), FLAGS_pbfr_size,
                                        "session"};
  if (!parse<SMTP::greeting, SMTP::action>(in, *conn)) {
    LOG(WARNING) << "greeting was unrecognizable";
    close(fd);
    return {};
  }
  if (!conn->greeting_ok) {
    LOG(WARNING) << "greeting was not in the affirmative";
    close(fd);
    return {};
  }

  // EHLO/HELO

  auto use_esmtp = FLAGS_use_esmtp;
  if (use_esmtp) {
    LOG(INFO) << "C: EHLO " << sender.ascii();
    conn->sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;
    if (!parse<SMTP::ehlo_rsp, SMTP::action>(in, *conn) || !conn->ehlo_ok) {
      LOG(WARNING) << "EHLO response was unrecognizable, trying HELO";
      use_esmtp = false;
    }
  }
  if (!use_esmtp) {
    LOG(INFO) << "C: HELO " << sender.ascii();
    conn->sock.out() << "HELO " << sender.ascii() << "\r\n" << std::flush;
    if (!parse<SMTP::helo_ok_rsp, SMTP::action>(in, *conn)) {
      LOG(WARNING) << "HELO response was unrecognizable";
      close(fd);
      return {};
    }
  }

  // STARTTLS

  if (conn->has_extension("STARTTLS")) {
    LOG(INFO) << "C: STARTTLS";
    conn->sock.out() << "STARTTLS\r\n" << std::flush;
    if (!parse<SMTP::reply_lines, SMTP::action>(in, *conn)) {
      LOG(WARNING) << "STARTTLS response was unrecognizable";
      close(fd);
      return {};
    }

    DNS::RR_collection tlsa_rrs; // FIXME
    if (!conn->sock.starttls_client(config_path, sender.ascii().c_str(),
                                    mx.ascii().c_str(), tlsa_rrs, false)) {
      LOG(WARNING) << "failed to STARTTLS";
      close(fd);
      return {};
    }
  }

  return std::optional<std::unique_ptr<SMTP::Connection>>(std::move(conn));
}

bool do_mail_from(SMTP::Connection& conn, Mailbox from)
{
  auto in{istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size,
                                      "mail_from"}};

  std::ostringstream param_stream;
  // param_stream << " SIZE=" << total_size;

  if (conn.has_extension("BINARYMIME")) {
    param_stream << " BODY=BINARYMIME";
  }
  else if (conn.has_extension("8BITMIME")) {
    param_stream << " BODY=8BITMIME";
  }

  if (conn.has_extension("SMTPUTF8")) {
    param_stream << " SMTPUTF8";
  }

  auto const param_str = param_stream.str();

  LOG(INFO) << "C: MAIL FROM:<" << from << '>' << param_str;
  conn.sock.out() << "MAIL FROM:<" << from << '>' << param_str << "\r\n"
                  << std::flush;
  if (!parse<SMTP::reply_lines, SMTP::action>(in, conn)) {
    LOG(ERROR) << "MAIL FROM: reply unparseable";
    return false;
  }
  if (conn.reply_code.at(0) != '2') {
    LOG(WARNING) << "MAIL FROM: negative reply " << conn.reply_code;
    return false;
  }

  conn.mail_from = from;
  return true;
}

bool do_rcpt_to(SMTP::Connection& conn, Mailbox from, Mailbox to)
{
  if (conn.mail_from != from) {
    do_mail_from(conn, from);
  }

  if (std::find(begin(conn.rcpt_to), end(conn.rcpt_to), to)
      != end(conn.rcpt_to)) {
    LOG(INFO) << to << " already in recpt_to list of " << conn.server_id;
    return true;
  }

  auto in{
      istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size, "rcpt_to"}};

  LOG(INFO) << "C: RCPT TO:<" << to << '>';
  conn.sock.out() << "RCPT TO:<" << to << ">\r\n" << std::flush;
  if (!parse<SMTP::reply_lines, SMTP::action>(in, conn)) {
    LOG(ERROR) << "RCPT TO: reply unparseable";
    return false;
  }
  if (conn.reply_code.at(0) != '2') {
    LOG(WARNING) << "RCPT TO: negative reply " << conn.reply_code;
    return false;
  }

  conn.rcpt_to.emplace_back(to);
  return true;
}

bool do_data(SMTP::Connection& conn, std::istream& is)
{
  auto in{
      istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size, "session"}};
  LOG(INFO) << "C: DATA";
  conn.sock.out() << "DATA\r\n" << std::flush;
  if (!parse<SMTP::reply_lines, SMTP::action>(in, conn)) {
    LOG(ERROR) << "DATA command reply unparseable";
    return false;
  }
  if (conn.reply_code != "354") {
    LOG(ERROR) << "DATA returned " << conn.reply_code;
    return false;
  }

  auto lineno = 0;
  auto line{std::string{}};

  while (std::getline(is, line)) {
    ++lineno;
    if (!conn.sock.out().good()) {
      conn.sock.log_stats();
      LOG(ERROR) << "output no good at line " << lineno;
      return false;
    }
    if (line.length() && (line.at(0) == '.')) {
      conn.sock.out() << '.';
    }
    conn.sock.out() << line;
    if (line.back() != '\r') {
      LOG(WARNING) << "bare new line in message body at line " << lineno;
      conn.sock.out() << '\r';
    }
    conn.sock.out() << '\n';
  }
  if (!conn.sock.out().good()) {
    LOG(ERROR) << "socket error of some sort after DATA";
    return false;
  }

  // Done!
  conn.sock.out() << ".\r\n" << std::flush;

  if (!parse<SMTP::reply_lines, SMTP::action>(in, conn)) {
    LOG(ERROR) << "DATA reply unparseable";
    return false;
  }

  LOG(INFO) << "reply_code == " << conn.reply_code;
  return conn.reply_code.at(0) == '2';
}

bool do_bdat(SMTP::Connection& conn, std::istream& is)
{
  auto in
      = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size, "bdat"};
  auto                  bdat_error = false;
  std::streamsize const bfr_size   = 1024 * 1024;
  iobuffer<char>        bfr(bfr_size);

  while (!is.eof()) {
    is.read(bfr.data(), bfr_size);
    auto const size_read = is.gcount();

    conn.sock.out() << "BDAT " << size_read << "\r\n";
    LOG(INFO) << "C: BDAT " << size_read;

    conn.sock.out().write(bfr.data(), size_read);
    conn.sock.out() << std::flush;

    if (!parse<SMTP::reply_lines, SMTP::action>(in, conn)) {
      LOG(ERROR) << "BDAT reply unparseable";
      bdat_error = true;
      break;
    }
    if (conn.reply_code != "250") {
      LOG(ERROR) << "BDAT returned " << conn.reply_code;
      bdat_error = true;
      break;
    }
  }

  conn.sock.out() << "BDAT 0 LAST\r\n" << std::flush;
  LOG(INFO) << "C: BDAT 0 LAST";

  CHECK((parse<SMTP::reply_lines, SMTP::action>(in, conn)));
  if (conn.reply_code != "250") {
    LOG(ERROR) << "BDAT 0 LAST returned " << conn.reply_code;
    return false;
  }

  return !bdat_error;
}

bool do_send(SMTP::Connection& conn, std::istream& is)
{
  if (conn.has_extension("CHUNKING"))
    return do_bdat(conn, is);
  return do_data(conn, is);
}

bool do_rset(SMTP::Connection& conn)
{
  auto in
      = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size, "rset"};
  LOG(INFO) << "C: RSET";
  conn.sock.out() << "RSET\r\n" << std::flush;
  return parse<SMTP::reply_lines, SMTP::action>(in, conn);
}

bool do_quit(SMTP::Connection& conn)
{
  auto in
      = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_pbfr_size, "quit"};
  LOG(INFO) << "C: QUIT";
  conn.sock.out() << "QUIT\r\n" << std::flush;
  return parse<SMTP::reply_lines, SMTP::action>(in, conn);
}

} // namespace

Send::Send(fs::path config_path)
  : config_path_(config_path)
{
}

bool Send::mail_from(Mailbox const& mailbox)
{
  SRS        srs;
  auto const fwd
      = srs.forward(mailbox.as_string().c_str(), sender_.ascii().c_str());
  if (Mailbox::validate(fwd))
    mail_from_ = Mailbox(fwd);

  for (auto& [mx, conn] : exchangers_) {
    conn->mail_from.clear();
    conn->rcpt_to.clear();
  }
  return true;
}

bool Send::rcpt_to(DNS::Resolver& res,
                   Mailbox const& to,
                   std::string&   error_msg)
{
  if (mail_from_.empty()) {
    LOG(WARNING) << "sequence error, must have MAIL FROM: before RCPT TO:";
    return false;
  }

  // Check for existing receivers entry.
  if (auto rec = receivers_.find(to.domain()); rec != receivers_.end()) {
    if (auto ex = exchangers_.find(rec->second); ex != exchangers_.end()) {
      auto& conn = ex->second;
      return do_rcpt_to(*conn, mail_from_, to);
    }
    LOG(ERROR) << "found a receiver but not an exchanger "
               << "from == " << mail_from_ << "  to == " << to;
    return false;
  }

  // Get a connection to an MX for this domain
  std::vector<Domain> mxs = get_mxs(res, to.domain());
  CHECK(!mxs.empty());
  for (auto& mx : mxs) {
    // Check for existing connection.
    if (auto ex = exchangers_.find(mx); ex != exchangers_.end()) {
      LOG(INFO) << "found existing connection to " << mx;
      receivers_.emplace(to.domain(), mx);
      auto& conn = ex->second;
      return do_rcpt_to(*conn, mail_from_, to);
    }
    // Open new connection.
    if (auto new_conn
        = open_session(res, config_path_, mail_from_.domain(), mx);
        new_conn) {
      LOG(INFO) << "opened new connection to " << mx;
      exchangers_.emplace(mx, std::move(*new_conn));
      auto ex = exchangers_.find(mx);
      CHECK(ex != exchangers_.end());
      receivers_.emplace(to.domain(), mx);
      auto& conn = ex->second;
      return do_rcpt_to(*conn, mail_from_, to);
    }
  }

  LOG(WARNING) << "ran out of mail exchangers for " << to;
  return false;
}

bool Send::send(char const* dp_in, size_t length_in)
{
  auto const sender = sender_.ascii().c_str();
  auto [dp, length] = rewrite(sender, dp_in, length_in);

  // FIXME this needs to be done in parallel
  for (auto& [dom, conn] : exchangers_) {
    if (!conn->rcpt_to.empty()) {
      auto is{imemstream{dp.get(), length}};
      if (!do_send(*conn, is)) {
        LOG(WARNING) << "failed to send to " << conn->server_id;
        return false;
      }
    }
    else {
      LOG(INFO) << "no receivers, skipping MX " << dom;
    }
    conn->mail_from.clear();
    conn->rcpt_to.clear();
  }
  return true;
}

void Send::rset()
{
  for (auto& [dom, conn] : exchangers_) {
    if (!conn->rcpt_to.empty()) {
      if (!do_rset(*conn)) {
        LOG(WARNING) << "failed to rset " << conn->server_id;
      }
    }
    conn->mail_from.clear();
    conn->rcpt_to.clear();
  }
}

void Send::quit()
{
  for (auto& [dom, conn] : exchangers_) {
    do_quit(*conn);
    conn->sock.close_fds();
  }
  exchangers_.clear();
}

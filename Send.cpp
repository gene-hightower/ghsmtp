#include "Send.hpp"

#include <random>

#include "IP4.hpp"
#include "IP6.hpp"
#include "imemstream.hpp"

#include <gflags/gflags.h>

// This needs to be at least the length of each string it's trying to match.
DEFINE_uint64(bfr_size, 4 * 1024, "parser buffer size");

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

namespace RFC5321 {

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
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.server_id = in.string();
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
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.greeting_ok = true;
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
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_ok = true;
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
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_keyword = in.string();
    boost::to_upper(cnn.ehlo_keyword);
  }
};

template <>
struct action<ehlo_param> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_param.push_back(in.string());
  }
};

template <>
struct action<ehlo_line> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_params.emplace(std::move(cnn.ehlo_keyword),
                            std::move(cnn.ehlo_param));
  }
};

template <>
struct action<reply_lines> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
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
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.reply_code = in.string();
  }
};
} // namespace RFC5321

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

  if (nmx)
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
    in4.sin_port = htons(port);
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

} // namespace

Send::Send(fs::path config_path, Domain sender, Domain receiver)
  : config_path_(config_path)
  , sender_(sender)
  , receiver_(receiver)
{
}

bool open_session(DNS::Resolver& res,
                  Exchangers&    exchangers,
                  fs::path       config_path,
                  Domain         sender,
                  Domain         receiver,
                  Domain         mx)
{
  int fd = conn(res, mx, 25);
  if (fd == -1) {
    LOG(WARNING) << mx << " no connection";
    return false;
  }

  // Listen for greeting

  auto constexpr read_hook{[]() {}};
  auto conn = std::make_unique<RFC5321::Connection>(fd, fd, read_hook);

  auto in
      = istream_input<eol::crlf, 1>{conn->sock.in(), FLAGS_bfr_size, "session"};
  if (!parse<RFC5321::greeting, RFC5321::action>(in, *conn)) {
    LOG(WARNING) << "greeting was unrecognizable";
    close(fd);
    return false;
  }
  if (!conn->greeting_ok) {
    LOG(WARNING) << "greeting was not in the affirmative";
    close(fd);
    return false;
  }

  // EHLO/HELO

  auto use_esmtp = FLAGS_use_esmtp;
  if (use_esmtp) {
    LOG(INFO) << "C: EHLO " << sender.ascii();
    conn->sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;

    if (!parse<RFC5321::ehlo_rsp, RFC5321::action>(in, *conn)
        || !conn->ehlo_ok) {
      LOG(WARNING) << "EHLO response was unrecognizable, trying HELO";
      use_esmtp = false;
    }
  }
  if (!use_esmtp) {
    LOG(INFO) << "C: HELO " << sender.ascii();
    conn->sock.out() << "HELO " << sender.ascii() << "\r\n" << std::flush;
    if (!parse<RFC5321::helo_ok_rsp, RFC5321::action>(in, *conn)) {
      LOG(WARNING) << "HELO response was unrecognizable";
      close(fd);
      return false;
    }
  }

  // STARTTLS

  if (conn->has_extension("STARTTLS")) {
    LOG(INFO) << "C: STARTTLS";
    conn->sock.out() << "STARTTLS\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, *conn)));

    DNS::RR_collection tlsa_rrs;
    CHECK(conn->sock.starttls_client(config_path, sender.ascii().c_str(),
                                     receiver.ascii().c_str(), tlsa_rrs,
                                     false));
  }

  exchangers.add(mx, std::move(conn));
  return true;
}

bool Send::connect(DNS::Resolver& res, Exchangers& exchangers)
{
  if (mxs_.empty())
    mxs_ = get_mxs(res, receiver_);
  CHECK(!mxs_.empty());

  for (auto const& mx : mxs_) {
    if (exchangers.contains(mx)) {
      // LOG(INFO) << "already connected to " << mx;
      return true;
    }
    LOG(INFO) << "trying " << mx;
    if (!open_session(res, exchangers, config_path_, sender_, receiver_, mx)) {
      LOG(WARNING) << "can't open session";
      return false;
    }
    mx_active_ = mx;
    LOG(INFO) << "connected to " << mx;
    return true;
  }

  LOG(WARNING) << "can't connect to any MXs for " << receiver_;
  return false;
}

bool Send::mail_from(Exchangers& exchangers, Mailbox mailbox)
{
  if (sender_ != mailbox.domain()) {
    LOG(WARNING) << "mailbox " << mailbox << " not in sending domain "
                 << sender_;
  }
  CHECK(!mxs_.empty());
  CHECK(exchangers.contains(mx_active_));
  RFC5321::Connection& conn = exchangers.conn(mx_active_);
  auto in = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_bfr_size,
                                        "mail_from"};

  LOG(INFO) << "C: MAIL FROM";
  conn.sock.out() << "MAIL FROM:<" << mailbox << ">\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, conn)));
  return true;
}

bool Send::rcpt_to(Exchangers& exchangers, Mailbox mailbox)
{
  if (receiver_ != mailbox.domain()) {
    LOG(WARNING) << "mailbox " << mailbox << " not in receiving domain "
                 << receiver_;
  }
  CHECK(!mxs_.empty());
  CHECK(exchangers.contains(mx_active_));
  RFC5321::Connection& conn = exchangers.conn(mx_active_);
  auto                 in
      = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_bfr_size, "rcpt_to"};

  LOG(INFO) << "C: RCPT TO:";
  conn.sock.out() << "RCPT TO:<" << mailbox << ">\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, conn)));
  return true;
}

bool Send::data(Exchangers& exchangers, char const* data, size_t length)
{
  CHECK(!mxs_.empty());
  CHECK(exchangers.contains(mx_active_));
  RFC5321::Connection& conn = exchangers.conn(mx_active_);
  auto in = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_bfr_size, "quit"};
  LOG(INFO) << "C: DATA";
  conn.sock.out() << "DATA\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, conn)));
  if (conn.reply_code != "354") {
    LOG(ERROR) << "DATA returned " << conn.reply_code;
    return false;
  }

  // Done!
  conn.sock.out() << ".\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, conn)));

  LOG(INFO) << "reply_code == " << conn.reply_code;
  return conn.reply_code.at(0) == '2';
}

void Send::quit(Exchangers& exchangers)
{
  CHECK(!mxs_.empty());
  CHECK(exchangers.contains(mx_active_));
  RFC5321::Connection& conn = exchangers.conn(mx_active_);
  auto in = istream_input<eol::crlf, 1>{conn.sock.in(), FLAGS_bfr_size, "quit"};
  LOG(INFO) << "C: QUIT";
  conn.sock.out() << "QUIT\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, conn)));
}

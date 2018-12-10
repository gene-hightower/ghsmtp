// Toy program to send email.  This is used to test my SMTP server,
// mostly.  It's overgrown a bit.

#include <gflags/gflags.h>
namespace gflags {
// in case we didn't have one
}

// This needs to be at least the length of each string it's trying to match.
DEFINE_uint64(bfr_size, 4 * 1024, "parser buffer size");

DEFINE_bool(selftest, false, "run a self test");

DEFINE_bool(pipe, false, "send to stdin/stdout");

DEFINE_bool(to_the_neck, false, "shove data forever");
DEFINE_bool(slow_strangle, false, "super slow mo");
DEFINE_bool(long_line, false, "super long text line");
DEFINE_bool(bare_lf, false, "send a bare LF");
DEFINE_bool(huge_size, false, "attempt with huge size");
DEFINE_bool(badpipline, false, "send two NOOPs back-to-back");
DEFINE_bool(nosend, false, "don't actually send any mail");
DEFINE_bool(noconn, false, "don't connect to any host");
DEFINE_bool(rawdog,
            false,
            "send the body exactly as is, don't fix CRLF issues "
            "or escape leading dots");

DEFINE_bool(use_esmtp, true, "use ESMTP (EHLO)");

DEFINE_bool(use_8bitmime, true, "use 8BITMIME extension");
DEFINE_bool(use_binarymime, true, "use BINARYMIME extension");
DEFINE_bool(use_chunking, true, "use CHUNKING extension");
DEFINE_bool(use_pipelining, true, "use PIPELINING extension");
DEFINE_bool(use_size, true, "use SIZE extension");
DEFINE_bool(use_smtputf8, true, "use SMTPUTF8 extension");
DEFINE_bool(use_tls, true, "use STARTTLS extension");

DEFINE_bool(require_tls, true, "use STARTTLS or die");

// To force it, set if you have UTF8 in the local part of any RFC5321
// address.
DEFINE_bool(force_smtputf8, false, "force SMTPUTF8 extension");

DEFINE_string(sender, "", "FQDN of sending node");

DEFINE_string(local_address, "", "local address to bind");
DEFINE_string(mx_host, "", "FQDN of receiving node");
DEFINE_string(service, "smtp-test", "service name");
DEFINE_string(client_id, "", "client name (ID) for EHLO/HELO");

DEFINE_string(from, "", "RFC5322 From: address");
DEFINE_string(from_name, "", "RFC5322 From: name");

DEFINE_string(to, "", "RFC5322 To: address");
DEFINE_string(to_name, "", "RFC5322 To: name");

DEFINE_string(smtp_from, "", "RFC5321 MAIL FROM address");
DEFINE_string(smtp_to, "", "RFC5321 RCPT TO address");

DEFINE_string(subject, "testing one, two, three...", "RFC5322 Subject");
DEFINE_string(keywords, "", "RFC5322 Keywords: header");
DEFINE_string(references, "", "RFC5322 References: header");
DEFINE_string(in_reply_to, "", "RFC5322 In-Reply-To: header");
DEFINE_string(reply_to, "", "RFC5322 Reply-To: header");

DEFINE_bool(4, false, "use only IP version 4");
DEFINE_bool(6, false, "use only IP version 6");

DEFINE_string(username, "", "AUTH username");
DEFINE_string(password, "", "AUTH password");

DEFINE_bool(use_dkim, true, "sign with DKIM");
DEFINE_string(selector, "ghsmtp", "DKIM selector");
DEFINE_string(dkim_key_file, "", "DKIM key file");

#include "Base64.hpp"
#include "DKIM.hpp"
#include "DNS-fcrdns.hpp"
#include "DNS.hpp"
#include "Domain.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "Magic.hpp"
#include "Mailbox.hpp"
#include "Message.hpp"
#include "Now.hpp"
#include "Pill.hpp"
#include "Sock.hpp"
#include "fs.hpp"
#include "imemstream.hpp"
#include "osutil.hpp"
#include "sa.hpp"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>

using namespace std::string_literals;

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string/case_conv.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace Config {
constexpr auto read_timeout = std::chrono::seconds(30);
constexpr auto write_timeout = std::chrono::minutes(3);
} // namespace Config

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

namespace RFC5322 {

struct VUCHAR : sor<VCHAR, chars::non_ascii> {};

using dot = one<'.'>;
using colon = one<':'>;

// All 7-bit ASCII except NUL (0), LF (10) and CR (13).
struct text_ascii : ranges<1, 9, 11, 12, 14, 127> {};

// Short lines of ASCII text.  LF or CRLF line separators.
struct body_ascii : seq<star<seq<rep_max<998, text_ascii>, eol>>,
                             opt<rep_max<998, text_ascii>>, eof> {};

struct text_utf8 : sor<text_ascii, chars::non_ascii> {};

// Short lines of UTF-8 text.  LF or CRLF line separators.
struct body_utf8 : seq<star<seq<rep_max<998, text_utf8>, eol>>,
                            opt<rep_max<998, text_utf8>>, eof> {};

struct FWS : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

struct qtext : sor<one<33>, ranges<35, 91, 93, 126>, chars::non_ascii> {};

struct quoted_pair : seq<one<'\\'>, sor<VUCHAR, WSP>> {};

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

// ctext is ASCII not '(' or ')' or '\\'
struct ctext : sor<ranges<33, 39, 42, 91, 93, 126>, chars::non_ascii> {};

struct comment;

struct ccontent : sor<ctext, quoted_pair, comment> {};

struct comment
    : seq<one<'('>, star<seq<opt<FWS>, ccontent>>, opt<FWS>, one<')'>> {};

struct CFWS : sor<seq<plus<seq<opt<FWS>, comment>, opt<FWS>>>, FWS> {};

struct qcontent : sor<qtext, quoted_pair> {};

// Corrected in errata ID: 3135
struct quoted_string
    : seq<opt<CFWS>,
          DQUOTE,
          sor<seq<star<seq<opt<FWS>, qcontent>>, opt<FWS>>, FWS>,
          DQUOTE,
          opt<CFWS>> {};

// *([FWS] VCHAR) *WSP
struct unstructured : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {};

struct atom : seq<opt<CFWS>, plus<atext>, opt<CFWS>> {};

struct dot_atom_text : list<plus<atext>, dot> {};

struct dot_atom : seq<opt<CFWS>, dot_atom_text, opt<CFWS>> {};

struct word : sor<atom, quoted_string> {};

struct phrase : plus<word> {};

struct local_part : sor<dot_atom, quoted_string> {};

// from '!' to '~' excluding 91 92 93 '[' '\\' ']'

struct dtext : ranges<33, 90, 94, 126> {};

struct domain_literal : seq<opt<CFWS>,
                            one<'['>,
                            star<seq<opt<FWS>, dtext>>,
                            opt<FWS>,
                            one<']'>,
                            opt<CFWS>> {};

struct domain : sor<dot_atom, domain_literal> {};

struct addr_spec : seq<local_part, one<'@'>, domain> {};

struct postmaster : TAOCPP_PEGTL_ISTRING("Postmaster") {};

struct addr_spec_or_postmaster : sor<addr_spec, postmaster> {};

struct addr_spec_only : seq<addr_spec_or_postmaster, eof> {};

struct display_name : phrase {};

struct display_name_only : seq<display_name, eof> {};

// clang-format on

// struct name_addr : seq<opt<display_name>, angle_addr> {};

// struct mailbox : sor<name_addr, addr_spec> {};

template <typename Rule>
struct inaction : nothing<Rule> {
};

template <typename Rule>
struct action : nothing<Rule> {
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
struct action<domain> {
  template <typename Input>
  static void apply(Input const& in, Mailbox& mbx)
  {
    mbx.set_domain(in.string());
  }
};
} // namespace RFC5322

namespace RFC5321 {

struct Connection {
  Sock sock;

  std::string server_id;

  std::string ehlo_keyword;
  std::vector<std::string> ehlo_param;
  std::unordered_map<std::string, std::vector<std::string>> ehlo_params;

  std::string reply_code;

  bool greeting_ok{false};
  bool ehlo_ok{false};

  Connection(int fd_in, int fd_out, std::function<void(void)> read_hook)
    : sock(
          fd_in, fd_out, read_hook, Config::read_timeout, Config::write_timeout)
  {
  }
};

// clang-format off

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {};

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
struct mailbox_only : seq<mailbox, eof> {};

// textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

struct textstring : plus<sor<one<9>, range<32, 126>>> {};

struct server_id : sor<domain, address_literal> {};

// Greeting       = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF )
//                  /
//                  ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
//                 *( "220-" [ textstring ] CRLF )
//                    "220 " [ textstring ] CRLF )

struct greeting_ok
: sor<seq<TAOCPP_PEGTL_ISTRING("220 "), server_id, opt<textstring>, CRLF>,
      seq<TAOCPP_PEGTL_ISTRING("220-"), server_id, opt<textstring>, CRLF,
 star<seq<TAOCPP_PEGTL_ISTRING("220-"), opt<textstring>, CRLF>>,
      seq<TAOCPP_PEGTL_ISTRING("220 "), opt<textstring>, CRLF>>> {};

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
: sor<seq<TAOCPP_PEGTL_ISTRING("250 "), server_id, opt<ehlo_greet>, CRLF>,

      seq<TAOCPP_PEGTL_ISTRING("250-"), server_id, opt<ehlo_greet>, CRLF,
 star<seq<TAOCPP_PEGTL_ISTRING("250-"), ehlo_line, CRLF>>,
      seq<TAOCPP_PEGTL_ISTRING("250 "), opt<ehlo_line>, CRLF>>
      > {};

struct ehlo_rsp
  : sor<ehlo_ok_rsp, reply_lines> {};

struct helo_ok_rsp
  : seq<TAOCPP_PEGTL_ISTRING("250 "), server_id, opt<ehlo_greet>, CRLF> {};

struct auth_login_username
    : seq<TAOCPP_PEGTL_STRING("334 VXNlcm5hbWU6"), CRLF> {};

struct auth_login_password
    : seq<TAOCPP_PEGTL_STRING("334 UGFzc3dvcmQ6"), CRLF> {};

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
    imemstream stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << " S: " << line;
    }
  }
};

template <>
struct action<ehlo_ok_rsp> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_ok = true;
    imemstream stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << " S: " << line;
    }
  }
};

template <>
struct action<ehlo_keyword> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_keyword = in.string();
  }
};

template <>
struct action<ehlo_param> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_param.push_back(in.string());
    boost::to_upper(cnn.ehlo_param.back());
  }
};

template <>
struct action<ehlo_line> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    boost::to_upper(cnn.ehlo_keyword);
    cnn.ehlo_params.emplace(std::move(cnn.ehlo_keyword),
                            std::move(cnn.ehlo_param));
  }
};

template <>
struct action<reply_lines> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    imemstream stream{begin(in), size(in)};
    std::string line;
    while (std::getline(stream, line)) {
      LOG(INFO) << " S: " << line;
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

int conn(DNS::Resolver& res, Domain const& node, uint16_t port)
{
  auto const use_4{!FLAGS_6};
  auto const use_6{!FLAGS_4};

  if (use_6) {
    auto const fd{socket(AF_INET6, SOCK_STREAM, 0)};
    PCHECK(fd >= 0) << "socket() failed";

    if (!FLAGS_local_address.empty()) {
      auto loc{sockaddr_in6{}};
      loc.sin6_family = AF_INET6;
      if (1
          != inet_pton(AF_INET6, FLAGS_local_address.c_str(),
                       reinterpret_cast<void*>(&loc.sin6_addr))) {
        LOG(FATAL) << "can't interpret " << FLAGS_local_address
                   << " as IPv6 address";
      }
      PCHECK(0 == bind(fd, reinterpret_cast<sockaddr*>(&loc), sizeof(loc)));
    }

    auto addrs{std::vector<std::string>{}};

    if (node.is_address_literal()) {
      if (IP6::is_address(node.ascii())) {
        addrs.push_back(node.ascii());
      }
    }
    else {
      addrs = res.get_strings(DNS::RR_type::AAAA, node.ascii());
    }
    for (auto const& addr : addrs) {
      auto in6{sockaddr_in6{}};
      in6.sin6_family = AF_INET6;
      in6.sin6_port = htons(port);
      CHECK_EQ(inet_pton(AF_INET6, addr.c_str(),
                         reinterpret_cast<void*>(&in6.sin6_addr)),
               1);
      if (connect(fd, reinterpret_cast<const sockaddr*>(&in6), sizeof(in6))) {
        PLOG(WARNING) << "connect failed [" << addr << "]:" << port;
        continue;
      }

      LOG(INFO) << " connected to [" << addr << "]:" << port;
      return fd;
    }

    close(fd);
  }
  if (use_4) {
    auto fd{socket(AF_INET, SOCK_STREAM, 0)};
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

      LOG(INFO) << "connected to " << addr << ":" << port;
      return fd;
    }

    close(fd);
  }

  return -1;
}

class Eml {
public:
  void add_hdr(std::string name, std::string value)
  {
    hdrs_.push_back(std::make_pair(name, value));
  }

  void foreach_hdr(std::function<void(std::string const& name,
                                      std::string const& value)> func)
  {
    for (auto const& [name, value] : hdrs_) {
      func(name, value);
    }
  }

private:
  std::vector<std::pair<std::string, std::string>> hdrs_;

  friend std::ostream& operator<<(std::ostream& os, Eml const& eml)
  {
    for (auto const& [name, value] : eml.hdrs_) {
      os << name << ": " << value << "\r\n";
    }
    return os << "\r\n"; // end of headers
  }
};

// // clang-format off
// char const* const signhdrs[] = {
//     "From",

//     "Message-ID",

//     "Cc",
//     "Date",
//     "In-Reply-To",
//     "References",
//     "Reply-To",
//     "Sender",
//     "Subject",
//     "To",

//     "MIME-Version",
//     "Content-Type",
//     "Content-Transfer-Encoding",

//     nullptr
// };
// clang-format on

enum class transfer_encoding {
  seven_bit,
  quoted_printable,
  base64,
  eight_bit,
  binary,
};

enum class data_type {
  ascii,  // 7bit, quoted-printable and base64
  utf8,   // 8bit
  binary, // binary
};

data_type type(std::string_view d)
{
  {
    auto in{memory_input<>{d.data(), d.size(), "data"}};
    if (parse<RFC5322::body_ascii>(in)) {
      return data_type::ascii;
    }
  }
  {
    auto in{memory_input<>{d.data(), d.size(), "data"}};
    if (parse<RFC5322::body_utf8>(in)) {
      return data_type::utf8;
    }
  }
  // anything else is
  return data_type::binary;
}

class content {
public:
  content(char const* path)
    : path_(path)
  {
    auto const body_sz{fs::file_size(path_)};
    CHECK(body_sz) << "no body";
    file_.open(path_);
    type_ = ::type(*this);
  }

  char const* data() const { return file_.data(); }
  size_t size() const { return file_.size(); }
  data_type type() const { return type_; }

  bool empty() const { return size() == 0; }
  operator std::string_view() const { return std::string_view(data(), size()); }

private:
  data_type type_;
  fs::path path_;
  boost::iostreams::mapped_file_source file_;
};

template <typename Input>
void fail(Input& in, RFC5321::Connection& cnn)
{
  LOG(INFO) << " C: QUIT";
  cnn.sock.out() << "QUIT\r\n" << std::flush;
  // we might have a few error replies stacked up if we're pipelining
  // CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  exit(EXIT_FAILURE);
}

template <typename Input>
void check_for_fail(Input& in, RFC5321::Connection& cnn, std::string_view cmd)
{
  cnn.sock.out() << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  if (cnn.reply_code.at(0) != '2') {
    LOG(ERROR) << cmd << " returned " << cnn.reply_code;
    fail(in, cnn);
  }
  in.discard();
}

bool validate_name(const char* flagname, std::string const& value)
{
  if (value.empty()) // empty name needs to validate, but
    return true;     // will not be used
  memory_input<> name_in(value.c_str(), "name");
  if (!parse<RFC5322::display_name_only, RFC5322::inaction>(name_in)) {
    LOG(ERROR) << "bad name syntax " << value;
    return false;
  }
  return true;
}

DEFINE_validator(from_name, &validate_name);
DEFINE_validator(to_name, &validate_name);

bool validate_address_RFC5322(const char* flagname, std::string const& value)
{
  if (value.empty()) // empty name needs to validate, but
    return true;     // will not be used
  memory_input<> name_in(value.c_str(), "address");
  if (!parse<RFC5322::addr_spec_only, RFC5322::inaction>(name_in)) {
    LOG(ERROR) << "bad address syntax " << value;
    return false;
  }
  return true;
}

DEFINE_validator(from, &validate_address_RFC5322);
DEFINE_validator(to, &validate_address_RFC5322);

bool validate_address_RFC5321(const char* flagname, std::string const& value)
{
  if (value.empty()) // empty name needs to validate, but
    return true;     // will not be used
  memory_input<> name_in(value.c_str(), "mailbox");
  if (!parse<RFC5321::mailbox_only, RFC5321::inaction>(name_in)) {
    LOG(ERROR) << "bad address syntax " << value;
    return false;
  }
  return true;
}

DEFINE_validator(smtp_from, &validate_address_RFC5321);
DEFINE_validator(smtp_to, &validate_address_RFC5321);

void selftest()
{
  CHECK(validate_name("selftest", ""s));
  CHECK(validate_name("selftest", "Elmer J Fudd"s));
  CHECK(validate_name("selftest", "\"Elmer J. Fudd\""s));
  CHECK(validate_name("selftest", "Elmer! J! Fudd!"s));

  CHECK(validate_address_RFC5321("selftest", "foo@digilicious.com"s));
  CHECK(validate_address_RFC5321("selftest", "\"foo\"@digilicious.com"s));
  CHECK(validate_address_RFC5321(
      "selftest",
      "\"very.(),:;<>[]\\\".VERY.\\\"very@\\\\ \\\"very\\\".unusual\"@digilicious.com"s));

  CHECK(validate_address_RFC5322("selftest", "foo@digilicious.com"s));
  CHECK(validate_address_RFC5322("selftest", "\"foo\"@digilicious.com"s));
  CHECK(validate_address_RFC5322(
      "selftest",
      "\"very.(),:;<>[]\\\".VERY.\\\"very@\\\\ \\\"very\\\".unusual\"@digilicious.com"s));

  auto const read_hook{[]() {}};

  const char* greet_list[]{
      "220-mtaig-aak03.mx.aol.com ESMTP Internet Inbound\r\n"
      "220-AOL and its affiliated companies do not\r\n"
      "220-authorize the use of its proprietary computers and computer\r\n"
      "220-networks to accept, transmit, or distribute unsolicited bulk\r\n"
      "220-e-mail sent from the internet.\r\n"
      "220-Effective immediately:\r\n"
      "220-AOL may no longer accept connections from IP addresses\r\n"
      "220 which no do not have reverse-DNS (PTR records) assigned.\r\n",

      "421 mtaig-maa02.mx.aol.com Service unavailable - try again later\r\n",
  };

  for (auto i : greet_list) {
    auto cnn{RFC5321::Connection(0, 1, read_hook)};
    auto in{memory_input<>{i, i}};
    if (!parse<RFC5321::greeting, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing greeting \"" << i << "\"";
    }
    if (cnn.greeting_ok) {
      LOG(WARNING) << "greeting ok";
    }
    else {
      LOG(WARNING) << "greeting was not in the affirmative";
    }
  }

  const char* ehlo_rsp_list[]{
      "250-HELLO, SAILOR!\r\n"
      "250-NO-SOLICITING\r\n"
      "250 8BITMIME\r\n",

      "250-digilicious.com at your service, localhost. [IPv6:::1]\r\n"
      "250-SIZE 15728640\r\n"
      "250-8BITMIME\r\n"
      "250-STARTTLS\r\n"
      "250-ENHANCEDSTATUSCODES\r\n"
      "250-PIPELINING\r\n"
      "250-BINARYMIME\r\n"
      "250-CHUNKING\r\n"
      "250 SMTPUTF8\r\n",

      "500 5.5.1 command unrecognized: \"EHLO digilicious.com\\r\\n\"\r\n",

      "250-263xmail at your service\r\n"
      "250-STARTTLS\r\n"
      "250-MAE-SMTP\r\n"
      "250-263.net\r\n" // the '.' is not RFC complaint
      "250-SIZE 104857600\r\n"
      "250-ETRN\r\n"
      "250-ENHANCEDSTATUSCODES\r\n"
      "250-8BITMIME\r\n"
      "250 DSN\r\n",
  };

  for (auto i : ehlo_rsp_list) {
    auto cnn{RFC5321::Connection(0, 1, read_hook)};
    auto in{memory_input<>{i, i}};
    if (!parse<RFC5321::ehlo_rsp, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing ehlo response \"" << i << "\"";
    }
    if (cnn.ehlo_ok) {
      LOG(WARNING) << "ehlo ok";
    }
    else {
      LOG(WARNING) << "ehlo response was not in the affirmative";
    }
  }
}

auto get_sender()
{
  if (FLAGS_sender.empty()) {
    FLAGS_sender = {[] {
      if (!FLAGS_client_id.empty())
        return FLAGS_client_id;

      auto const id_from_env{getenv("GHSMTP_CLIENT_ID")};
      if (id_from_env)
        return std::string{id_from_env};

      auto const hostname{osutil::get_hostname()};
      if (hostname.find('.') != std::string::npos)
        return hostname;

      LOG(FATAL) << "can't determine my server ID, set GHSMTP_CLIENT_ID maybe";
    }()};
  };

  auto const sender{Domain{FLAGS_sender}};

  if (FLAGS_from.empty()) {
    FLAGS_from = "test-it@"s + sender.utf8();
  }

  if (FLAGS_to.empty()) {
    FLAGS_to = "test-it@"s + sender.utf8();
  }

  return sender;
}

bool is_localhost(DNS::RR const& rr)
{
  if (std::holds_alternative<DNS::RR_MX>(rr)) {
    if (iequal(std::get<DNS::RR_MX>(rr).exchange(), "localhost"))
      return true;
  }
  return false;
}

bool starts_with(std::string_view str, std::string_view prefix)
{
  if (str.size() >= prefix.size())
    if (str.compare(0, prefix.size(), prefix) == 0)
      return true;
  return false;
}

bool sts_rec(std::string const& sts_rec)
{
  return starts_with(sts_rec, "v=STSv1");
}

std::vector<Domain>
get_receivers(DNS::Resolver& res, Mailbox const& to_mbx, bool& enforce_dane)
{
  auto receivers{std::vector<Domain>{}};

  // User provided explicit host to receive mail.
  if (!FLAGS_mx_host.empty()) {
    receivers.emplace_back(FLAGS_mx_host);
    return receivers;
  }

  // Non-local part is an address literal.
  if (to_mbx.domain().is_address_literal()) {
    receivers.emplace_back(to_mbx.domain());
    return receivers;
  }

  // RFC 5321 section 5.1 "Locating the Target Host"

  // “The lookup first attempts to locate an MX record associated with
  //  the name.  If a CNAME record is found, the resulting name is
  //  processed as if it were the initial name.”

  // Our (full) resolver will traverse any CNAMEs for us and return
  // the CNAME and MX records all together.

  auto const& domain = to_mbx.domain().ascii();

  auto q_sts{DNS::Query{res, DNS::RR_type::TXT, "_mta-sts."s + domain}};
  if (q_sts.has_record()) {
    auto sts_records = q_sts.get_strings();
    sts_records.erase(std::remove_if(begin(sts_records), end(sts_records),
                                     std::not_fn(sts_rec)),
                      end(sts_records));
    if (size(sts_records) == 1) {
      LOG(INFO) << "### This domain implements MTA-STS ###";
    }
  }
  else {
    LOG(INFO) << "MTA-STS record not found for domain " << domain;
  }

  auto q{DNS::Query{res, DNS::RR_type::MX, domain}};
  if (q.authentic_data()) {
    LOG(INFO) << "### MX records authentic for domain " << domain << " ###";
  }
  else {
    LOG(INFO) << "MX records can't be authenticated for domain " << domain;
    enforce_dane = false;
  }
  auto mxs{q.get_records()};

  mxs.erase(std::remove_if(begin(mxs), end(mxs), is_localhost), end(mxs));

  auto const nmx = std::count_if(begin(mxs), end(mxs), [](auto const& rr) {
    return std::holds_alternative<DNS::RR_MX>(rr);
  });

  if (nmx == 1) {
    for (auto const& mx : mxs) {
      if (std::holds_alternative<DNS::RR_MX>(mx)) {
        // RFC 7505 null MX record
        if ((std::get<DNS::RR_MX>(mx).preference() == 0)
            && (std::get<DNS::RR_MX>(mx).exchange().empty()
                || (std::get<DNS::RR_MX>(mx).exchange() == "."))) {
          LOG(INFO) << "domain " << domain << " does not accept mail";
          return receivers;
        }
      }
    }
  }

  if (nmx == 0) {
    // implicit MX RR
    receivers.emplace_back(domain);
    return receivers;
  }

  // […] then the sender-SMTP MUST randomize them to spread the load
  // across multiple mail exchangers for a specific organization.
  std::shuffle(begin(mxs), end(mxs), std::random_device());
  std::sort(begin(mxs), end(mxs), [](auto const& a, auto const& b) {
    if (std::holds_alternative<DNS::RR_MX>(a)
        && std::holds_alternative<DNS::RR_MX>(b)) {
      return std::get<DNS::RR_MX>(a).preference()
             < std::get<DNS::RR_MX>(b).preference();
    }
    return false;
  });

  if (nmx)
    LOG(INFO) << "MXs for " << domain << " are:";

  for (auto const& mx : mxs) {
    if (std::holds_alternative<DNS::RR_MX>(mx)) {
      receivers.emplace_back(std::get<DNS::RR_MX>(mx).exchange());
      LOG(INFO) << std::setfill(' ') << std::setw(3)
                << std::get<DNS::RR_MX>(mx).preference() << " "
                << std::get<DNS::RR_MX>(mx).exchange();
    }
  }

  return receivers;
}

auto parse_mailboxes()
{
  auto from_mbx{Mailbox{}};
  auto from_in{memory_input<>{FLAGS_from, "from"}};
  if (!parse<RFC5322::addr_spec_only, RFC5322::action>(from_in, from_mbx)) {
    LOG(FATAL) << "bad From: address syntax <" << FLAGS_from << ">";
  }
  LOG(INFO) << " from_mbx == " << from_mbx;

  auto local_from{memory_input<>{from_mbx.local_part(), "from.local"}};
  FLAGS_force_smtputf8 |= !parse<chars::ascii_only>(local_from);

  auto to_mbx{Mailbox{}};
  auto to_in{memory_input<>{FLAGS_to, "to"}};
  if (!parse<RFC5322::addr_spec_only, RFC5322::action>(to_in, to_mbx)) {
    LOG(FATAL) << "bad To: address syntax <" << FLAGS_to << ">";
  }
  LOG(INFO) << " to_mbx == " << to_mbx;

  auto local_to{memory_input<>{to_mbx.local_part(), "to.local"}};
  FLAGS_force_smtputf8 |= !parse<chars::ascii_only>(local_to);

  auto smtp_from_mbx{Mailbox{}};
  auto smtp_from_in{memory_input<>{FLAGS_smtp_from, "SMTP.from"}};
  if (!FLAGS_smtp_from.empty()) {
    if (!parse<RFC5321::mailbox_only, RFC5321::action>(smtp_from_in,
                                                       smtp_from_mbx)) {
      LOG(FATAL) << "bad MAIL FROM: address syntax <" << FLAGS_smtp_from << ">";
    }
    LOG(INFO) << " smtp_from_mbx == " << smtp_from_mbx;
    auto local_smtp_from{
        memory_input<>{smtp_from_mbx.local_part(), "SMTP.from.local"}};
    FLAGS_force_smtputf8 |= !parse<chars::ascii_only>(local_smtp_from);
  }

  auto smtp_to_mbx{Mailbox{}};
  auto smtp_to_in{memory_input<>{FLAGS_smtp_to, "SMTP.to"}};
  if (!FLAGS_smtp_to.empty()) {
    if (!parse<RFC5321::mailbox_only, RFC5321::action>(smtp_to_in,
                                                       smtp_to_mbx)) {
      LOG(FATAL) << "bad RCPT TO: address syntax <" << FLAGS_smtp_to << ">";
    }
    LOG(INFO) << " smtp_to_mbx == " << smtp_to_mbx;

    auto local_smtp_to{
        memory_input<>{smtp_to_mbx.local_part(), "SMTP.to.local"}};
    FLAGS_force_smtputf8 |= !parse<chars::ascii_only>(local_smtp_to);
  }

  return std::make_tuple(from_mbx, to_mbx, smtp_from_mbx, smtp_to_mbx);
}

auto create_eml(Domain const& sender,
                std::string const& from,
                std::string const& to,
                std::vector<content> const& bodies,
                bool ext_smtputf8)
{
  auto eml{Eml{}};
  auto const date{Now{}};
  auto const pill{Pill{}};

  auto mid_str = fmt::format("<{}.{}@{}>", date.sec(), pill, sender.utf8());
  eml.add_hdr("Message-ID", mid_str.c_str());
  eml.add_hdr("Date", date.c_str());

  if (!FLAGS_from_name.empty())
    eml.add_hdr("From", fmt::format("{} <{}>", FLAGS_from_name, from));
  else
    eml.add_hdr("From", from);

  if (!FLAGS_to_name.empty())
    eml.add_hdr("To", fmt::format("{} <{}>", FLAGS_to_name, to));
  else
    eml.add_hdr("To", to);

  eml.add_hdr("Subject", FLAGS_subject);

  if (!FLAGS_keywords.empty())
    eml.add_hdr("Keywords", FLAGS_keywords);

  if (!FLAGS_references.empty())
    eml.add_hdr("References", FLAGS_references);

  if (!FLAGS_in_reply_to.empty())
    eml.add_hdr("In-Reply-To", FLAGS_in_reply_to);

  if (!FLAGS_reply_to.empty())
    eml.add_hdr("Reply-To", FLAGS_reply_to);

  eml.add_hdr("MIME-Version", "1.0");
  eml.add_hdr("Content-Language", "en-US");

  auto magic{Magic{}}; // to ID buffer contents

  eml.add_hdr("Content-Type", magic.buffer(bodies[0]));

  return eml;
}

void sign_eml(Eml& eml,
              Mailbox const& from_mbx,
              std::vector<content> const& bodies)
{
  auto const body_type = (bodies[0].type() == data_type::binary)
                             ? OpenDKIM::Sign::body_type::binary
                             : OpenDKIM::Sign::body_type::text;

  auto key_file = FLAGS_dkim_key_file.empty() ? (FLAGS_selector + ".private")
                                              : FLAGS_dkim_key_file;
  std::ifstream keyfs(key_file.c_str());
  CHECK(keyfs.good()) << "can't access " << key_file;
  std::string key(std::istreambuf_iterator<char>{keyfs}, {});
  OpenDKIM::Sign dks(key.c_str(), FLAGS_selector.c_str(),
                     from_mbx.domain().ascii().c_str(), body_type);
  eml.foreach_hdr([&dks](std::string const& name, std::string const& value) {
    auto header = name + ": "s + value;
    dks.header(header.c_str());
  });
  dks.eoh();
  for (auto const& body : bodies) {
    dks.body(body);
  }
  dks.eom();
  eml.add_hdr("DKIM-Signature"s, dks.getsighdr());
}

template <typename Input>
void do_auth(Input& in, RFC5321::Connection& cnn)
{
  if (FLAGS_username.empty() && FLAGS_password.empty())
    return;

  auto const auth = cnn.ehlo_params.find("AUTH");
  if (auth == end(cnn.ehlo_params)) {
    LOG(ERROR) << "server doesn't support AUTH";
    fail(in, cnn);
  }

  // Perfer PLAIN mechanism.
  if (std::find(begin(auth->second), end(auth->second), "PLAIN")
      != end(auth->second)) {
    LOG(INFO) << "C: AUTH PLAIN";
    auto tok{std::ostringstream{}};
    tok.str().reserve(FLAGS_username.length() + FLAGS_password.length() + 2);
    tok << '\0' << FLAGS_username << '\0' << FLAGS_password;
    cnn.sock.out() << "AUTH PLAIN " << Base64::enc(tok.str()) << "\r\n"
                   << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    if (cnn.reply_code != "235") {
      LOG(ERROR) << "AUTH PLAIN returned " << cnn.reply_code;
      fail(in, cnn);
    }
  }
  // The LOGIN SASL mechanism is obsolete.
  else if (std::find(begin(auth->second), end(auth->second), "LOGIN")
           != end(auth->second)) {
    LOG(INFO) << "C: AUTH LOGIN";
    cnn.sock.out() << "AUTH LOGIN\r\n" << std::flush;
    CHECK((parse<RFC5321::auth_login_username>(in)));
    cnn.sock.out() << Base64::enc(FLAGS_username) << "\r\n" << std::flush;
    CHECK((parse<RFC5321::auth_login_password>(in)));
    cnn.sock.out() << Base64::enc(FLAGS_password) << "\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    if (cnn.reply_code != "235") {
      LOG(ERROR) << "AUTH LOGIN returned " << cnn.reply_code;
      fail(in, cnn);
    }
  }
  else {
    LOG(ERROR) << "server doesn't support AUTH methods PLAIN or LOGIN";
    fail(in, cnn);
  }
}

// Do various bad things during the DATA transfer.

template <typename Input>
void bad_daddy(Input& in, RFC5321::Connection& cnn)
{
  LOG(INFO) << "C: DATA";
  cnn.sock.out() << "DATA\r\n";
  cnn.sock.out() << std::flush;

  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  if (cnn.reply_code != "354") {
    LOG(ERROR) << "DATA returned " << cnn.reply_code;
    fail(in, cnn);
  }

  // cnn.sock.out() << "\r\nThis ->\n<- is a bare LF!\r\n";
  if (FLAGS_bare_lf)
    cnn.sock.out() << "\n.\n\r\n";

  if (FLAGS_to_the_neck) {
    for (;;) {
      cnn.sock.out() << "####################"
                        "####################"
                        "####################"
                     << std::flush;
    }
  }

  if (FLAGS_long_line) {
    for (auto i = 0; i < 10000; ++i) {
      cnn.sock.out() << 'X';
    }
    cnn.sock.out() << "\r\n" << std::flush;
  }

  while (FLAGS_slow_strangle) {
    for (auto i = 0; i < 100; ++i) {
      cnn.sock.out() << 'X' << std::flush;
      sleep(3);
    }
    cnn.sock.out() << "\r\n";
  }

  // Done!
  cnn.sock.out() << ".\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

  LOG(INFO) << "reply_code == " << cnn.reply_code;
  CHECK_EQ(cnn.reply_code.at(0), '2');

  LOG(INFO) << "C: QUIT";
  cnn.sock.out() << "QUIT\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
}

bool snd(int fd_in,
         int fd_out,
         Domain const& sender,
         Domain const& receiver,
         DNS::RR_collection const& tlsa_rrs,
         bool enforce_dane,
         Mailbox const& from_mbx,
         Mailbox const& to_mbx,
         Mailbox const& smtp_from_mbx,
         Mailbox const& smtp_to_mbx,
         std::vector<content> const& bodies)
{
  auto constexpr read_hook{[]() {}};

  auto cnn{RFC5321::Connection(fd_in, fd_out, read_hook)};

  auto in{istream_input<eol::crlf>{cnn.sock.in(), FLAGS_bfr_size, "session"}};
  if (!parse<RFC5321::greeting, RFC5321::action>(in, cnn)) {
    LOG(WARNING) << "can't parse greeting";
    return false;
  }

  if (!cnn.greeting_ok) {
    LOG(WARNING) << "greeting was not in the affirmative, skipping";
    return false;
  }

  // try EHLO/HELO

  if (FLAGS_use_esmtp) {
    LOG(INFO) << "C: EHLO " << sender.ascii();
    cnn.sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;

    CHECK((parse<RFC5321::ehlo_rsp, RFC5321::action>(in, cnn)));
    if (!cnn.ehlo_ok) {

      if (FLAGS_force_smtputf8) {
        LOG(WARNING) << "ehlo response was not in the affirmative, skipping";
        return false;
      }

      LOG(WARNING) << "ehlo response was not in the affirmative, trying HELO";
      FLAGS_use_esmtp = false;
    }
  }

  if (!FLAGS_use_esmtp) {
    LOG(INFO) << "C: HELO " << sender.ascii();
    cnn.sock.out() << "HELO " << sender.ascii() << "\r\n" << std::flush;
    if (!parse<RFC5321::helo_ok_rsp, RFC5321::action>(in, cnn)) {
      LOG(WARNING) << "HELO didn't work, skipping";
      return false;
    }
  }

  // Check extensions

  auto bad_dad = FLAGS_bare_lf || FLAGS_slow_strangle || FLAGS_to_the_neck;

  if (bad_dad) {
    FLAGS_use_chunking = false;
    FLAGS_use_size = false;
  }

  auto const ext_8bitmime{
      FLAGS_use_8bitmime
      && (cnn.ehlo_params.find("8BITMIME") != end(cnn.ehlo_params))};

  auto const ext_chunking{FLAGS_use_chunking
                          && cnn.ehlo_params.find("CHUNKING")
                                 != end(cnn.ehlo_params)};

  auto const ext_binarymime{FLAGS_use_binarymime && ext_chunking
                            && cnn.ehlo_params.find("BINARYMIME")
                                   != end(cnn.ehlo_params)};
  auto const ext_pipelining{
      FLAGS_use_pipelining
      && (cnn.ehlo_params.find("PIPELINING") != end(cnn.ehlo_params))};

  auto const ext_size{FLAGS_use_size
                      && cnn.ehlo_params.find("SIZE") != end(cnn.ehlo_params)};

  auto const ext_smtputf8{
      FLAGS_use_smtputf8
      && (cnn.ehlo_params.find("SMTPUTF8") != end(cnn.ehlo_params))};

  auto const ext_starttls{
      FLAGS_use_tls
      && (cnn.ehlo_params.find("STARTTLS") != end(cnn.ehlo_params))};

  if (FLAGS_force_smtputf8 && !ext_smtputf8) {
    LOG(WARNING) << "no SMTPUTF8, skipping";
    return false;
  }

  if (ext_starttls) {
    LOG(INFO) << "C: STARTTLS";
    cnn.sock.out() << "STARTTLS\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

    // LOG(INFO) << "cnn.sock.starttls_client(" << receiver.ascii() << ");";
    cnn.sock.starttls_client(sender.ascii().c_str(), receiver.ascii().c_str(),
                             tlsa_rrs, enforce_dane);

    LOG(INFO) << "TLS: " << cnn.sock.tls_info();

    LOG(INFO) << "C: EHLO " << sender.ascii();
    cnn.sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;
    CHECK((parse<RFC5321::ehlo_ok_rsp, RFC5321::action>(in, cnn)));
  }
  else if (FLAGS_require_tls) {
    LOG(ERROR) << "No TLS extension, won't send mail in plain text without "
                  "--require_tls=false.";
    LOG(INFO) << "C: QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_FAILURE);
  }

  if (receiver != cnn.server_id) {
    LOG(INFO) << "server identifies as " << cnn.server_id;
  }

  if (FLAGS_force_smtputf8 && !ext_smtputf8) {
    LOG(WARNING) << "does not support SMTPUTF8";
    return false;
  }

  if (ext_smtputf8 && !ext_8bitmime) {
    LOG(ERROR)
        << "SMTPUTF8 requires 8BITMIME, see RFC-6531 section 3.1 item 8.";
    LOG(INFO) << "C: QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_FAILURE);
  }

  auto max_msg_size{0u};
  if (ext_size) {
    if (!cnn.ehlo_params["SIZE"].empty()) {
      char* ep = nullptr;
      max_msg_size = strtoul(cnn.ehlo_params["SIZE"][0].c_str(), &ep, 10);
      if (ep && (*ep != '\0')) {
        LOG(WARNING) << "garbage in SIZE argument: "
                     << cnn.ehlo_params["SIZE"][0];
      }
    }
  }

  do_auth(in, cnn);

  in.discard();

  auto enc = FLAGS_force_smtputf8 ? Mailbox::encoding::utf8
                                  : Mailbox::encoding::ascii;

  std::string from = smtp_from_mbx.empty() ? from_mbx.as_string(enc)
                                           : smtp_from_mbx.as_string(enc);
  std::string to = smtp_to_mbx.empty() ? to_mbx.as_string(enc)
                                       : smtp_to_mbx.as_string(enc);

  auto eml{create_eml(sender, from, to, bodies, ext_smtputf8)};

  if (FLAGS_use_dkim) {
    sign_eml(eml, from_mbx, bodies);
  }

  // Get the header as one big string
  std::ostringstream hdr_stream;
  hdr_stream.str().reserve(2 * 1024);
  hdr_stream << eml;
  auto const& hdr_str = hdr_stream.str();

  // In the case of DATA style transfer, this total_size number is an
  // *estimate* only, as line endings may be translated or added
  // during transfer.  In the BDAT case, this number must be exact.

  auto total_size = hdr_str.size();
  for (auto const& body : bodies)
    total_size += body.size();

  if (ext_size && max_msg_size && (total_size > max_msg_size)) {
    LOG(ERROR) << "message size " << total_size << " exceeds size limit of "
               << max_msg_size;
    LOG(INFO) << "C: QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_FAILURE);
  }

  std::ostringstream param_stream;
  param_stream.str().reserve(100);
  if (FLAGS_huge_size && ext_size) {
    // Claim some huge size.
    param_stream << " SIZE=" << std::numeric_limits<std::streamsize>::max();
  }
  else if (ext_size) {
    param_stream << " SIZE=" << total_size;
  }

  if (ext_binarymime) {
    param_stream << " BODY=BINARYMIME";
  }
  else if (ext_8bitmime) {
    param_stream << " BODY=8BITMIME";
  }

  if (ext_smtputf8) {
    param_stream << " SMTPUTF8";
  }

  if (FLAGS_badpipline) {
    LOG(INFO) << "C: NOOP NOOP";
    cnn.sock.out() << "NOOP\r\nNOOP\r\n" << std::flush;
  }

  auto param_str = param_stream.str();

  LOG(INFO) << "C: MAIL FROM:<" << from << '>' << param_str;
  cnn.sock.out() << "MAIL FROM:<" << from << '>' << param_str << "\r\n";
  if (!ext_pipelining) {
    check_for_fail(in, cnn, "MAIL FROM");
  }

  LOG(INFO) << "C: RCPT TO:<" << to << ">";
  cnn.sock.out() << "RCPT TO:<" << to << ">\r\n";
  if (!ext_pipelining) {
    check_for_fail(in, cnn, "RCPT TO");
  }

  if (FLAGS_nosend) {
    LOG(INFO) << "C: QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    if (ext_pipelining) {
      check_for_fail(in, cnn, "MAIL FROM");
      check_for_fail(in, cnn, "RCPT TO");
    }
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    LOG(INFO) << "no-sending";
    exit(EXIT_SUCCESS);
  }

  if (bad_dad) {
    if (ext_pipelining) {
      cnn.sock.out() << std::flush;
      check_for_fail(in, cnn, "MAIL FROM");
      check_for_fail(in, cnn, "RCPT TO");
    }
    bad_daddy(in, cnn);
    return true;
  }

  auto msg = std::make_unique<Message>();

  // if service is smtp (i.e. sending real mail, not smtp-test)
  try {
    msg->open(sender.ascii(), total_size * 2, ".Sent");
    msg->write(hdr_str.data(), hdr_str.size());
    for (auto const& body : bodies) {
      msg->write(body.data(), body.size());
    }
  }
  catch (std::system_error const& e) {
    switch (errno) {
    case ENOSPC:
      msg->trash();
      msg.reset();
      LOG(FATAL) << "no space";

    default:
      msg->trash();
      msg.reset();
      LOG(ERROR) << "errno==" << errno << ": " << strerror(errno);
      LOG(FATAL) << e.what();
    }
  }
  catch (std::exception const& e) {
    msg->trash();
    msg.reset();
    LOG(FATAL) << e.what();
  }

  if (ext_chunking) {
    std::ostringstream bdat_stream;
    bdat_stream.str().reserve(30);
    bdat_stream << "BDAT " << total_size << " LAST";
    LOG(INFO) << "C: " << bdat_stream.str();

    cnn.sock.out() << bdat_stream.str() << "\r\n";
    cnn.sock.out().write(hdr_str.data(), hdr_str.size());
    CHECK(cnn.sock.out().good());

    for (auto const& body : bodies) {
      cnn.sock.out().write(body.data(), body.size());
      CHECK(cnn.sock.out().good());
    }

    cnn.sock.out() << std::flush;
    CHECK(cnn.sock.out().good());

    // NOW check returns
    if (ext_pipelining) {
      check_for_fail(in, cnn, "MAIL FROM");
      check_for_fail(in, cnn, "RCPT TO");
    }

    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    if (cnn.reply_code != "250") {
      LOG(ERROR) << "BDAT returned " << cnn.reply_code;
      fail(in, cnn);
    }
  }
  else {
    LOG(INFO) << "C: DATA";
    cnn.sock.out() << "DATA\r\n";

    // NOW check returns
    if (ext_pipelining) {
      check_for_fail(in, cnn, "MAIL FROM");
      check_for_fail(in, cnn, "RCPT TO");
    }
    cnn.sock.out() << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    if (cnn.reply_code != "354") {
      LOG(ERROR) << "DATA returned " << cnn.reply_code;
      fail(in, cnn);
    }

    cnn.sock.out() << eml;

    for (auto const& body : bodies) {
      auto lineno = 0;
      auto line{std::string{}};
      auto isbody{imemstream{body.data(), body.size()}};
      while (std::getline(isbody, line)) {
        ++lineno;
        if (!cnn.sock.out().good()) {
          cnn.sock.log_stats();
          LOG(FATAL) << "output no good at line " << lineno;
        }
        if (FLAGS_rawdog) {
          // This adds a final newline at the end of the file, if no
          // line ending was present.
          cnn.sock.out() << line << '\n';
        }
        else {
          // This code converts single LF line endings into CRLF.
          // This code does nothing to fix single CR characters not
          // part of a CRLF pair.

          // This loop adds a CRLF and the end of the transmission if
          // the file doesn't already end with one.  This is a
          // requirement of the SMTP DATA protocol.

          if (line.length() && (line.at(0) == '.')) {
            cnn.sock.out() << '.';
          }
          cnn.sock.out() << line;
          if (line.back() != '\r')
            cnn.sock.out() << '\r';
          cnn.sock.out() << '\n';
        }
      }
    }
    CHECK(cnn.sock.out().good());

    // Done!
    cnn.sock.out() << ".\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  }
  if (cnn.reply_code.at(0) == '2') {
    msg->save();
    LOG(INFO) << "mail was sent successfully";
  }
  in.discard();

  LOG(INFO) << "C: QUIT";
  cnn.sock.out() << "QUIT\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

  return true;
}

DNS::RR_collection
get_tlsa_rrs(DNS::Resolver& res, Domain const& domain, uint16_t port)
{
  std::ostringstream tlsa;
  tlsa << '_' << port << "._tcp." << domain.ascii();

  DNS::Query q(res, DNS::RR_type::TLSA, tlsa.str());

  if (q.nx_domain()) {
    LOG(INFO) << "TLSA data not found for " << domain << ':' << port;
  }

  if (q.bogus_or_indeterminate()) {
    LOG(WARNING) << "TLSA data is bogus or indeterminate";
  }

  auto tlsa_rrs = q.get_records();
  if (!tlsa_rrs.empty()) {
    LOG(INFO) << "### TLSA data found for " << domain << ':' << port << " ###";
  }

  return tlsa_rrs;
}
} // namespace

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);

  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  auto sender = get_sender();

  if (FLAGS_selftest) {
    selftest();
    return 0;
  }

  auto bodies{std::vector<content>{}};
  for (int a = 1; a < argc; ++a) {
    if (!fs::exists(argv[a]))
      LOG(FATAL) << "can't find mail body part " << argv[a];
    bodies.push_back(argv[a]);
  }

  if (argc == 1)
    bodies.push_back("body.txt");

  CHECK_EQ(bodies.size(), 1) << "only one body part for now";
  CHECK(!(FLAGS_4 && FLAGS_6)) << "must use /some/ IP version";

  if (FLAGS_force_smtputf8)
    FLAGS_use_smtputf8 = true;

  auto&& [from_mbx, to_mbx, smtp_from_mbx, smtp_to_mbx] = parse_mailboxes();

  if (to_mbx.domain().empty() && FLAGS_mx_host.empty()) {
    LOG(ERROR) << "don't know who to send this mail to";
    return 0;
  }

  auto const port{osutil::get_port(FLAGS_service.c_str())};

  auto res{DNS::Resolver{}};
  auto tlsa_rrs{get_tlsa_rrs(res, to_mbx.domain(), port)};

  if (FLAGS_pipe) {
    return snd(STDIN_FILENO, STDOUT_FILENO, sender, to_mbx.domain(), tlsa_rrs,
               false, from_mbx, to_mbx, smtp_from_mbx, smtp_to_mbx, bodies)
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
  }

  bool enforce_dane = true;
  auto receivers = get_receivers(res, to_mbx, enforce_dane);

  if (receivers.empty()) {
    LOG(INFO) << "noplace to send this mail";
    return EXIT_SUCCESS;
  }

  for (auto const& receiver : receivers) {
    LOG(INFO) << "trying " << receiver << ":" << FLAGS_service;

    if (FLAGS_noconn) {
      LOG(INFO) << "skipping";
      continue;
    }

    auto fd = conn(res, receiver, port);
    if (fd == -1) {
      LOG(WARNING) << "bad connection, skipping";
      continue;
    }

    // Get our local IP address as "us".

    sa::sockaddrs us_addr{};
    socklen_t us_addr_len{sizeof us_addr};
    char us_addr_str[INET6_ADDRSTRLEN]{'\0'};
    std::vector<std::string> fcrdns;
    bool private_addr = false;

    if (-1 == getsockname(fd, &us_addr.addr, &us_addr_len)) {
      // Ignore ENOTSOCK errors from getsockname, useful for testing.
      PLOG_IF(WARNING, ENOTSOCK != errno) << "getsockname failed";
    }
    else {
      switch (us_addr_len) {
      case sizeof(sockaddr_in):
        PCHECK(inet_ntop(AF_INET, &us_addr.addr_in.sin_addr, us_addr_str,
                         sizeof us_addr_str)
               != nullptr);
        if (IP4::is_private(us_addr_str))
          private_addr = true;
        else
          fcrdns = DNS::fcrdns4(res, us_addr_str);
        break;

      case sizeof(sockaddr_in6):
        PCHECK(inet_ntop(AF_INET6, &us_addr.addr_in6.sin6_addr, us_addr_str,
                         sizeof us_addr_str)
               != nullptr);
        if (IP6::is_private(us_addr_str))
          private_addr = true;
        else
          fcrdns = DNS::fcrdns6(res, us_addr_str);
        break;

      default:
        LOG(FATAL) << "bogus address length (" << us_addr_len
                   << ") returned from getsockname";
      }
    }

    if (fcrdns.size()) {
      LOG(INFO) << "our names are:";
      for (auto const& fc : fcrdns) {
        LOG(INFO) << "    " << fc;
      }
    }

    if (!private_addr) {
      // look at from_mbx.domain() and get SPF records

      // also look at our ID to get SPF records.
    }

    if (to_mbx.domain() == receiver) {
      if (snd(fd, fd, sender, receiver, tlsa_rrs, enforce_dane, from_mbx,
              to_mbx, smtp_from_mbx, smtp_to_mbx, bodies)) {
        return EXIT_SUCCESS;
      }
    }
    else {
      auto tlsa_rrs_mx{get_tlsa_rrs(res, receiver, port)};
      tlsa_rrs_mx.insert(end(tlsa_rrs_mx), begin(tlsa_rrs), end(tlsa_rrs));
      if (snd(fd, fd, sender, receiver, tlsa_rrs_mx, enforce_dane, from_mbx,
              to_mbx, smtp_from_mbx, smtp_to_mbx, bodies)) {
        return EXIT_SUCCESS;
      }
    }

    close(fd);
  }

  LOG(ERROR) << "we ran out of hosts to try";
}

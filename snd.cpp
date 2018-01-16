// Toy program to send email.

#include <gflags/gflags.h>
namespace gflags {
// in case we didn't have one
}

DEFINE_bool(selftest, false, "run a self test");

DEFINE_bool(pipe, false, "send to stdin/stdout");

DEFINE_bool(nosend, false, "don't actually send any mail");
DEFINE_bool(rawdog,
            false,
            "send the body exactly as is, don't fix CRLF issues "
            "or escape leading dots");

DEFINE_bool(use_8bitmime, true, "use 8BITMIME extension to send mail");
DEFINE_bool(use_chunking, true, "use CHUNKING extension to send mail");
DEFINE_bool(use_pipelining, true, "use PIPELINING extension to send mail");
DEFINE_bool(use_size, true, "use SIZE extension");
DEFINE_bool(use_smtputf8, true, "use SMTPUTF8 extension");
DEFINE_bool(use_tls, true, "use STARTTLS extension");

DEFINE_string(sender, "", "FQDN of sending node");

DEFINE_string(local_address, "", "local address to bind");
DEFINE_string(mx_host, "localhost", "FQDN of receiving node");
DEFINE_string(service, "smtp-test", "service name");

DEFINE_string(from, "", "RFC5321 MAIL FROM address");
DEFINE_string(to, "", "RFC5321 RCPT TO address");

DEFINE_string(from_name, "\"Mr. Test It\"", "RFC5322 From: name");
DEFINE_string(to_name, "\"Mr. Test It\"", "RFC5322 To: name");

DEFINE_string(subject, "testing one, two, three...", "RFC5322 Subject");
DEFINE_string(keywords, "", "RFC5322 Keywords: header");
DEFINE_string(in_reply_to, "", "RFC5322 In-Reply-To: header");

DEFINE_bool(ip4, false, "use only IP version 4");
DEFINE_bool(ip6, false, "use only IP version 6");

DEFINE_string(username, "", "AUTH username");
DEFINE_string(password, "", "AUTH password");

DEFINE_string(selector, "ghsmtp", "DKIM selector");

#include "Base64.hpp"
#include "DKIM.hpp"
#include "DNS.hpp"
#include "Domain.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "Magic.hpp"
#include "Mailbox.hpp"
#include "Now.hpp"
#include "Pill.hpp"
#include "Sock.hpp"
#include "fs.hpp"
#include "hostname.hpp"
#include "imemstream.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_map>

using namespace std::string_literals;

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace Config {
constexpr std::streamsize max_msg_size = 150 * 1024 * 1024;
}

#include <boost/algorithm/string/case_conv.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace Config {
constexpr std::streamsize bfr_size = 4 * 1024;

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

// struct name_addr : seq<opt<display_name>, angle_addr> {};

// struct mailbox : sor<name_addr, addr_spec> {};

template <typename Rule>
struct inaction : nothing<Rule> {};

template <typename Rule>
struct action : nothing<Rule> {};

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
}

namespace RFC5321 {

struct Connection {
  Sock sock;

  std::string server_id;

  std::string ehlo_keyword;
  std::vector<std::string> ehlo_param;
  std::unordered_map<std::string, std::vector<std::string>> ehlo_params;

  std::string reply_code;

  bool ehlo_ok{false};

  Connection(int fd_in, int fd_out, std::function<void(void)> read_hook)
    : sock(fd_in, fd_out, read_hook, Config::read_timeout, Config::write_timeout)
  {}
};

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {};

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, chars::non_ascii> {};

// should verify last char is a U_Let_dig
struct u_ldh_str : plus<sor<ALPHA, DIGIT, chars::non_ascii, dash>> {};

struct u_label : seq<u_let_dig, opt<u_ldh_str>> {};

struct let_dig : sor<ALPHA, DIGIT> {};

// should verify last char is a U_Let_dig
struct ldh_str : plus<sor<ALPHA, DIGIT, dash>> {};

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

// textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

struct textstring : plus<sor<one<9>, range<32, 126>>> {};

struct server_id : sor<domain, address_literal> {};

// Greeting       = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF )
//                  /
//                  ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
//                 *( "220-" [ textstring ] CRLF )
//                    "220 " [ textstring ] CRLF )

struct greeting
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

// ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
//                    ; string of any characters other than CR or LF

struct ehlo_greet : plus<ranges<0, 9, 11, 12, 14, 127>> {};

// ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
//                  ; additional syntax of ehlo-params depends on
//                  ; ehlo-keyword

struct ehlo_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash>>> {};

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

struct ehlo_ok_rsp
: sor<seq<TAOCPP_PEGTL_ISTRING("250 "), server_id, opt<ehlo_greet>, CRLF>,

      seq<TAOCPP_PEGTL_ISTRING("250-"), server_id, opt<ehlo_greet>, CRLF,
 star<seq<TAOCPP_PEGTL_ISTRING("250-"), ehlo_line, CRLF>>,
      seq<TAOCPP_PEGTL_ISTRING("250 "), ehlo_line, CRLF>>
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
struct action<greeting> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    LOG(INFO) << "< " << in.string();
  }
};

template <>
struct action<ehlo_ok_rsp> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    cnn.ehlo_ok = true;
    LOG(INFO) << "< " << in.string();
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
    cnn.ehlo_params[cnn.ehlo_keyword] = cnn.ehlo_param;
    cnn.ehlo_keyword.clear();
    cnn.ehlo_param.clear();
  }
};

template <>
struct action<reply_lines> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    LOG(INFO) << "< " << in.string();
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

uint16_t get_port(char const* service)
{
  char* ep;
  auto service_no = strtoul(service, &ep, 10);
  if (*ep == '\0') {
    CHECK_LE(service_no, std::numeric_limits<uint16_t>::max());
    return static_cast<uint16_t>(service_no);
  }

  servent result_buf;
  servent* result_ptr;
  std::vector<char> str_buf(1024);
  while (getservbyname_r(service, "tcp", &result_buf, str_buf.data(),
                         str_buf.size(), &result_ptr)
         == ERANGE) {
    str_buf.resize(str_buf.size() * 2);
  }
  if (result_ptr == nullptr) {
    LOG(FATAL) << "service " << service << " unknown";
  }
  return ntohs(result_buf.s_port);
}

int conn(DNS::Resolver& res, Domain const& node, std::string const& service)
{
  bool use_4 = !FLAGS_ip6;
  bool use_6 = !FLAGS_ip4;

  auto port = get_port(service.c_str());
  if (use_6) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    PCHECK(fd >= 0) << "socket() failed";

    if (!FLAGS_local_address.empty()) {
      sockaddr_in6 loc{};
      loc.sin6_family = AF_INET6;
      if (1
          != inet_pton(AF_INET6, FLAGS_local_address.c_str(),
                       reinterpret_cast<void*>(&loc.sin6_addr))) {
        LOG(FATAL) << "can't interpret " << FLAGS_local_address
                   << " as IPv6 address";
      }
      PCHECK(0 == bind(fd, reinterpret_cast<sockaddr*>(&loc), sizeof(loc)));
    }

    std::vector<std::string> addrs;
    if (node.is_address_literal()) {
      if (IP6::is_address(node.ascii())) {
        addrs.push_back(node.address());
      }
    }
    else {
      addrs = DNS::get_records<DNS::RR_type::AAAA>(res, node.ascii());
    }
    for (auto addr : addrs) {
      sockaddr_in6 in6{};
      in6.sin6_family = AF_INET6;
      in6.sin6_port = htons(port);
      CHECK_EQ(inet_pton(AF_INET6, addr.c_str(),
                         reinterpret_cast<void*>(&in6.sin6_addr)),
               1);
      if (connect(fd, reinterpret_cast<const sockaddr*>(&in6), sizeof(in6))) {
        PLOG(WARNING) << "connect failed " << addr << ":" << port;
        continue;
      }

      LOG(INFO) << "connected to " << addr << ":" << port;
      return fd;
    }

    close(fd);
  }
  if (use_4) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    PCHECK(fd >= 0) << "socket() failed";

    if (!FLAGS_local_address.empty()) {
      sockaddr_in loc{};
      loc.sin_family = AF_INET;
      if (1
          != inet_pton(AF_INET, FLAGS_local_address.c_str(),
                       reinterpret_cast<void*>(&loc.sin_addr))) {
        LOG(FATAL) << "can't interpret " << FLAGS_local_address
                   << " as IPv4 address";
      }
      PCHECK(0 == bind(fd, reinterpret_cast<sockaddr*>(&loc), sizeof(loc)));
    }

    std::vector<std::string> addrs;
    if (node.is_address_literal()) {
      if (IP4::is_address_literal(node.ascii())) {
        addrs.push_back(node.address());
      }
    }
    else {
      addrs = DNS::get_records<DNS::RR_type::A>(res, node.ascii());
    }
    for (auto addr : addrs) {
      sockaddr_in in4{};
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
    for (auto const& h : hdrs_) {
      func(h.first, h.second);
    }
  }

private:
  std::vector<std::pair<std::string, std::string>> hdrs_;

  friend std::ostream& operator<<(std::ostream& os, Eml const& eml)
  {
    for (auto const& h : eml.hdrs_) {
      os << h.first << ": " << h.second << "\r\n";
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
  memory_input<> in(d.data(), d.size(), "data");
  if (parse<RFC5322::body_ascii>(in)) {
    return data_type::ascii;
  }
  if (parse<RFC5322::body_utf8>(in)) {
    return data_type::utf8;
  }
  // anything else is
  return data_type::binary;
}

class content {
public:
  content(char const* path)
    : path_(path)
  {
    auto body_sz = fs::file_size(path_);
    CHECK(body_sz) << "no body";
    file_.open(path_);
    data_ = file_.data();
    size_ = file_.size();
    type_ = ::type(*this);
  }

  char const* data() const { return data_; }
  size_t size() const { return size_; }
  data_type type() const { return type_; }

  bool empty() const { return size() == 0; }
  operator std::string_view() const { return std::string_view(data(), size()); }

private:
  char const* data_{nullptr};
  size_t size_{0};

  data_type type_;

  fs::path path_;
  boost::iostreams::mapped_file_source file_;
};

template <typename Input>
void fail(Input& in, RFC5321::Connection& cnn)
{
  LOG(INFO) << "> QUIT";
  cnn.sock.out() << "QUIT\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
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

std::string connectable_host(Domain const& dom)
{
  if (IP4::is_address_literal(dom.ascii()))
    return std::string(IP4::to_address(dom.ascii()));
  if (IP6::is_address_literal(dom.ascii()))
    return std::string(IP6::to_address(dom.ascii()));
  return dom.ascii();
}

std::string connectable_host(Mailbox mbx)
{
  return connectable_host(mbx.domain());
}

std::string connectable_host(std::string_view dom)
{
  return connectable_host(Domain(dom));
}

static bool validate_name(const char* flagname, std::string const& value)
{
  memory_input<> name_in(value.c_str(), "name");
  if (!parse<RFC5322::display_name_only, RFC5322::inaction>(name_in)) {
    LOG(ERROR) << "Bad name syntax " << value;
    return false;
  }
  return true;
}

DEFINE_validator(from_name, &validate_name);
DEFINE_validator(to_name, &validate_name);

void selftest()
{
  auto read_hook = []() {};
  static RFC5321::Connection cnn(0, 1, read_hook);

  const char* greet_list[]{
      "220-mtaig-aak03.mx.aol.com ESMTP Internet Inbound\r\n"
      "220-AOL and its affiliated companies do not\r\n"
      "220-authorize the use of its proprietary computers and computer\r\n"
      "220-networks to accept, transmit, or distribute unsolicited bulk\r\n"
      "220-e-mail sent from the internet.\r\n"
      "220-Effective immediately:\r\n"
      "220-AOL may no longer accept connections from IP addresses\r\n"
      "220 which no do not have reverse-DNS (PTR records) assigned.\r\n"};

  for (auto i : greet_list) {
    memory_input<> in(i, i);
    if (!parse<RFC5321::greeting, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing greeting \"" << i << "\"";
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
  };

  for (auto i : ehlo_rsp_list) {
    memory_input<> in(i, i);
    if (!parse<RFC5321::ehlo_rsp, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing ehlo response \"" << i << "\"";
    }
  }
}

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);

  if (FLAGS_sender.empty()) {
    const auto hostname = get_hostname();
    FLAGS_sender = hostname.c_str();
  }

  Domain sender(FLAGS_sender);

  if (FLAGS_from.empty()) {
    const auto from = "test-it@"s + sender.ascii();
    FLAGS_from = from;
  }

  if (FLAGS_to.empty()) {
    const auto to = "test-it@"s + sender.ascii();
    FLAGS_to = to;
  }

  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  if (FLAGS_selftest) {
    selftest();
    return 0;
  }

  CHECK(!(FLAGS_ip4 && FLAGS_ip6)) << "Must use /some/ IP version.";

  // parse FLAGS_from and FLAGS_to as addr_spec

  Mailbox from_mbx;
  memory_input<> from_in(FLAGS_from, "from");
  if (!parse<RFC5322::addr_spec_only, RFC5322::action>(from_in, from_mbx)) {
    LOG(FATAL) << "Bad From: address syntax <" << FLAGS_from << ">";
  }
  LOG(INFO) << "from_mbx == " << from_mbx;

  memory_input<> local_from(from_mbx.local_part(), "from.local");
  bool must_have_smtputf8 = !parse<chars::ascii_only>(local_from);

  Mailbox to_mbx;
  memory_input<> to_in(FLAGS_to, "to");
  if (!parse<RFC5322::addr_spec_only, RFC5322::action>(to_in, to_mbx)) {
    LOG(FATAL) << "Bad To: address syntax <" << FLAGS_to << ">";
  }
  LOG(INFO) << "to_mbx == " << to_mbx;

  memory_input<> local_in(to_mbx.local_part(), "to.local");
  must_have_smtputf8
      = must_have_smtputf8 || !parse<chars::ascii_only>(local_in);

  DNS::Resolver res;

  std::vector<Domain> receivers;
  if (!FLAGS_mx_host.empty()) {
    receivers.push_back(Domain(FLAGS_mx_host));
  }
  else {
    // look up MX records for to_mbx.domain()

    // returns list of servers sorted by priority, low to high
    auto mxs = DNS::get_records<DNS::RR_type::MX>(res, to_mbx.domain().ascii());

    // RFC 7505 null MX record
    if ((mxs.size() == 1) && (mxs.front() == ".")) {
      LOG(FATAL) << "domain does not accept mail";
    }

    if (mxs.empty()) {
      receivers.push_back(to_mbx.domain());
    }
    else {
      for (auto mx : mxs) {
        receivers.push_back(Domain(mx));
      }
    }
  }

try_host:
  int fd_in = 0;
  int fd_out = 1;

  if (!FLAGS_pipe) {
    CHECK(!receivers.empty()) << "no more hosts to try";
    LOG(INFO) << "trying " << receivers[0] << ":" << FLAGS_service;
    auto fd = conn(res, receivers[0], FLAGS_service);
    CHECK_NE(fd, -1);
    fd_in = fd;
    fd_out = fd;
  }

  auto read_hook = []() {};
  RFC5321::Connection cnn(fd_in, fd_out, read_hook);

  // CRLF /only/
  istream_input<eol::crlf> in(cnn.sock.in(), Config::bfr_size, "session");
  if (!parse<RFC5321::greeting, RFC5321::action>(in, cnn)) {
    LOG(WARNING) << "greeting failed to parse";
    if (fd_in == fd_out)
      close(fd_in);
    receivers.erase(receivers.begin());
    goto try_host;
  }

  LOG(INFO) << "> EHLO " << sender.ascii();
  cnn.sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;

  CHECK((parse<RFC5321::ehlo_rsp, RFC5321::action>(in, cnn)));
  if (!cnn.ehlo_ok) {
    LOG(WARNING) << "ehlo response did not parse";
    LOG(INFO) << "> HELO " << sender.ascii();
    cnn.sock.out() << "HELO " << sender.ascii() << "\r\n" << std::flush;
    CHECK((parse<RFC5321::helo_ok_rsp, RFC5321::action>(in, cnn)));
  }

  if (FLAGS_use_tls
      && (cnn.ehlo_params.find("STARTTLS") != cnn.ehlo_params.end())) {
    LOG(INFO) << "> STARTTLS";
    cnn.sock.out() << "STARTTLS\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

    cnn.sock.starttls_client();

    LOG(INFO) << "> EHLO " << sender.ascii();
    cnn.sock.out() << "EHLO " << sender.ascii() << "\r\n" << std::flush;
    CHECK((parse<RFC5321::ehlo_ok_rsp, RFC5321::action>(in, cnn)));
  }

  if (receivers[0] != cnn.server_id) {
    LOG(INFO) << "server identifies as " << cnn.server_id;
  }

  bool ext_smtputf8
      = FLAGS_use_smtputf8
        && cnn.ehlo_params.find("SMTPUTF8") != cnn.ehlo_params.end();

  if (must_have_smtputf8 && !ext_smtputf8) {
    if (fd_in == fd_out)
      close(fd_in);
    receivers.erase(receivers.begin());
    goto try_host;
  }

  bool ext_8bitmime
      = FLAGS_use_8bitmime
        && cnn.ehlo_params.find("8BITMIME") != cnn.ehlo_params.end();
  bool ext_chunking = cnn.ehlo_params.find("CHUNKING") != cnn.ehlo_params.end();
  bool ext_binarymime
      = cnn.ehlo_params.find("BINARYMIME") != cnn.ehlo_params.end();
  bool ext_pipelining
      = FLAGS_use_pipelining
        && (cnn.ehlo_params.find("PIPELINING") != cnn.ehlo_params.end());

  if (ext_binarymime && !ext_chunking) {
    LOG(WARNING)
        << "BINARYMIME implies CHUNKING, see RFC-3030 section 3 item 3.";
    ext_chunking = true;
  }

  if (ext_smtputf8 && !ext_8bitmime) {
    LOG(ERROR)
        << "SMTPUTF8 requires 8BITMIME, see RFC-6531 section 3.1 item 8.";
    LOG(INFO) << "> QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_FAILURE);
  }

  std::vector<content> bodies;

  if (argc == 1) {
    bodies.emplace_back("body.txt");
  }
  for (int a = 1; a < argc; ++a) {
    bodies.emplace_back(argv[a]);
  }

  CHECK_EQ(bodies.size(), 1) << "only one body part for now";

  auto max_msg_size = 0u;
  bool ext_size = cnn.ehlo_params.find("SIZE") != cnn.ehlo_params.end();
  if (ext_size) {
    if (!cnn.ehlo_params["SIZE"].empty()) {
      char* ep;
      max_msg_size = strtoul(cnn.ehlo_params["SIZE"][0].c_str(), &ep, 10);
      if (*ep != '\0') {
        LOG(WARNING) << "garbage in SIZE argument: "
                     << cnn.ehlo_params["SIZE"][0];
      }
    }
  }
  if (!max_msg_size) {
    max_msg_size = Config::max_msg_size;
  }

  if ((!FLAGS_username.empty()) && (!FLAGS_password.empty())) {
    auto auth = cnn.ehlo_params.find("AUTH");
    if (auth != cnn.ehlo_params.end()) {

      // Perfer PLAIN mechanism.
      if (std::find(auth->second.begin(), auth->second.end(), "PLAIN")
          != auth->second.end()) {
        LOG(INFO) << "> AUTH PLAIN";
        std::stringstream tok;
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
      else if (std::find(auth->second.begin(), auth->second.end(), "LOGIN")
               != auth->second.end()) {
        LOG(INFO) << "> AUTH LOGIN";
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
    else {
      LOG(ERROR) << "server doesn't support AUTH";
      fail(in, cnn);
    }
  }

  in.discard();

  std::string from = from_mbx;
  if (!ext_smtputf8) {
    from = from_mbx.local_part()
           + (from_mbx.domain().empty() ? ""
                                        : ("@" + from_mbx.domain().ascii()));
  }
  std::string to = to_mbx;
  if (!ext_smtputf8) {
    to = to_mbx.local_part()
         + (to_mbx.domain().empty() ? "" : ("@" + to_mbx.domain().ascii()));
  }

  Eml eml;

  Now date;
  Pill red, blue;
  std::stringstream mid_str;
  mid_str << '<' << date.sec() << '.' << red << '.' << blue << '@'
          << sender.utf8() << '>';
  eml.add_hdr("Message-ID", mid_str.str());

  eml.add_hdr("Date", date.c_str());

  std::string rfc5322_from = FLAGS_from_name + " <" + from + ">";
  eml.add_hdr("From", rfc5322_from);

  std::string rfc5322_to = FLAGS_to_name + " <" + to + ">";
  eml.add_hdr("To"s, rfc5322_to);

  eml.add_hdr("Subject", FLAGS_subject);

  if (!FLAGS_keywords.empty())
    eml.add_hdr("Keywords", FLAGS_keywords);

  if (!FLAGS_in_reply_to.empty())
    eml.add_hdr("In-Reply-To", FLAGS_in_reply_to);

  eml.add_hdr("MIME-Version", "1.0");
  eml.add_hdr("Content-Language", "en-US");

  Magic magic; // to ID buffer contents

  eml.add_hdr("Content-Type", magic.buffer(bodies[0]));

  auto body_type = (bodies[0].type() == data_type::binary)
                       ? OpenDKIM::Sign::body_type::binary
                       : OpenDKIM::Sign::body_type::text;

  auto key_file = FLAGS_selector + ".private";
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

  std::stringstream hdr_stream;
  hdr_stream << eml;
  auto hdr_str = hdr_stream.str();

  // In the case of DATA style transfer, this total_size number is an
  // *estimate* only, as line endings may be translated or added
  // during transfer.  In the BDAT case, this number must be exact.

  auto total_size = hdr_str.size();
  for (auto const& body : bodies)
    total_size += body.size();

  if (FLAGS_use_size && (total_size > max_msg_size)) {
    LOG(ERROR) << "message size " << total_size << " exceeds size limit of "
               << max_msg_size;
    LOG(INFO) << "> QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_FAILURE);
  }

  std::stringstream param_stream;
  if (FLAGS_use_size && ext_size) {
    param_stream << " SIZE=" << total_size;
  }

  if (ext_binarymime && FLAGS_use_chunking) {
    param_stream << " BODY=BINARYMIME";
  }
  else if (ext_8bitmime) {
    param_stream << " BODY=8BITMIME";
  }

  if (ext_smtputf8) {
    param_stream << " SMTPUTF8";
  }

  if (FLAGS_nosend) {
    LOG(INFO) << "> QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    exit(EXIT_SUCCESS);
  }

  auto param_str = param_stream.str();

  LOG(INFO) << "> MAIL FROM:<" << from << '>' << param_str;
  cnn.sock.out() << "MAIL FROM:<" << from << '>' << param_str << "\r\n";

  if (!ext_pipelining) {
    check_for_fail(in, cnn, "MAIL FROM");
  }

  LOG(INFO) << "> RCPT TO:<" << to << ">";
  cnn.sock.out() << "RCPT TO:<" << to << ">\r\n";

  if (!ext_pipelining) {
    check_for_fail(in, cnn, "RCPT TO");
  }

  if (FLAGS_use_chunking && ext_chunking) {
    std::stringstream bdat_stream;
    bdat_stream << "BDAT " << total_size << " LAST";
    LOG(INFO) << "> " << bdat_stream.str();

    cnn.sock.out() << bdat_stream.str() << "\r\n";
    cnn.sock.out().write(hdr_str.data(), hdr_str.size());
    CHECK(cnn.sock.out().good());

    for (auto const& body : bodies) {
      cnn.sock.out().write(body.data(), body.size());
    }
    CHECK(cnn.sock.out().good());

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
    LOG(INFO) << "> DATA";
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
      std::string line;
      imemstream isbody(body.data(), body.size());
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
    LOG(INFO) << "sent data";

    // Done!
    cnn.sock.out() << ".\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  }
  if (cnn.reply_code.at(0) == '2') {
    LOG(INFO) << "mail was sent successfully";
  }
  in.discard();

  LOG(INFO) << "> QUIT";
  cnn.sock.out() << "QUIT\r\n" << std::flush;
  CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

  return 0;
}

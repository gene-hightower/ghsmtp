#include <gflags/gflags.h>

DEFINE_bool(use_chunking, true, "Use CHUNKING extension to send mail");

DEFINE_string(sender, "digilicious.com", "FQDN of sending node");
DEFINE_string(receiver, "", "FQDN of receiving node");

DEFINE_string(service, "smtp", "service name");

DEFINE_string(from, "♥@digilicious.com", "rfc5321 MAIL FROM address");
DEFINE_string(to, "♥@digilicious.com", "rfc5321 RCPT TO address");

DEFINE_string(from_name, "基因", "rfc5322 From name");
DEFINE_string(to_name, "基因", "rfc5322 To name");

DEFINE_string(subject, "testing one, two, three…", "rfc5322 Subject");
// DEFINE_string(keywords, "🔑", "rfc5322 Keywords");
DEFINE_string(keywords, "keyword", "rfc5322 Keywords");

DEFINE_bool(ip_4, false, "use only IP version 4");
DEFINE_bool(ip_6, false, "use only IP version 6");

DEFINE_string(username, "", "AUTH username");
DEFINE_string(password, "", "AUTH password");

DEFINE_string(selector, "ghsmtp", "DKIM selector");

#include "DKIM.hpp"
#include "DNS.hpp"
#include "Domain.hpp"
#include "Mailbox.hpp"
#include "Now.hpp"
#include "Pill.hpp"
#include "Sock.hpp"
#include "hostname.hpp"
#include "imemstream.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <unordered_map>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <experimental/string_view>

namespace Config {
constexpr std::streamsize max_msg_size = 150 * 1024 * 1024;
}

#include <boost/algorithm/string/case_conv.hpp>

#define BOOST_FILESYSTEM_NO_DEPRECATED
#include <boost/filesystem.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

using std::experimental::string_view;

namespace Config {
constexpr std::streamsize bfr_size = 4 * 1024;

constexpr auto read_timeout = std::chrono::seconds(30);
constexpr auto write_timeout = std::chrono::minutes(3);
}

namespace UTF8 {
struct tail : range<0x80, 0xBF> {
};

struct ch_1 : range<0x00, 0x7F> {
};

struct ch_2 : seq<range<0xC2, 0xDF>, tail> {
};

struct ch_3 : sor<seq<one<0xE0>, range<0xA0, 0xBF>, tail>,
                  seq<range<0xE1, 0xEC>, rep<2, tail>>,
                  seq<one<0xED>, range<0x80, 0x9F>, tail>,
                  seq<range<0xEE, 0xEF>, rep<2, tail>>> {
};

struct ch_4 : sor<seq<one<0xF0>, range<0x90, 0xBF>, rep<2, tail>>,
                  seq<range<0xF1, 0xF3>, rep<3, tail>>,
                  seq<one<0xF4>, range<0x80, 0x8F>, rep<2, tail>>> {
};

// char = ch_1 | ch_2 | ch_3 | ch_4;

struct non_ascii : sor<ch_2, ch_3, ch_4> {
};
}

namespace RFC5322 {

struct VUCHAR : sor<VCHAR, UTF8::non_ascii> {
};

using dot = one<'.'>;
using colon = one<':'>;

struct text : sor<ranges<1, 9, 11, 12, 14, 127>, UTF8::non_ascii> {
};

struct body : seq<star<seq<rep_max<998, text>, eol>>, rep_max<998, text>> {
};

struct FWS : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {
};

struct qtext : sor<one<33>, ranges<35, 91, 93, 126>, UTF8::non_ascii> {
};

struct quoted_pair : seq<one<'\\'>, sor<VUCHAR, WSP>> {
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
                   UTF8::non_ascii> {
};
// clang-format on

// ctext is ASCII not '(' or ')' or '\\'
struct ctext : sor<ranges<33, 39, 42, 91, 93, 126>, UTF8::non_ascii> {
};

struct comment;

struct ccontent : sor<ctext, quoted_pair, comment> {
};

struct comment
    : seq<one<'('>, star<seq<opt<FWS>, ccontent>>, opt<FWS>, one<')'>> {
};

struct CFWS : sor<seq<plus<seq<opt<FWS>, comment>, opt<FWS>>>, FWS> {
};

struct qcontent : sor<qtext, quoted_pair> {
};

// Corrected in errata ID: 3135
struct quoted_string
    : seq<opt<CFWS>,
          DQUOTE,
          sor<seq<star<seq<opt<FWS>, qcontent>>, opt<FWS>>, FWS>,
          DQUOTE,
          opt<CFWS>> {
};
// *([FWS] VCHAR) *WSP
struct unstructured : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {
};

struct atom : seq<opt<CFWS>, plus<atext>, opt<CFWS>> {
};

struct dot_atom_text : list<plus<atext>, dot> {
};

struct dot_atom : seq<opt<CFWS>, dot_atom_text, opt<CFWS>> {
};

struct word : sor<atom, quoted_string> {
};

struct phrase : plus<word> {
};

// clang-format off
struct dec_octet : sor<one<'0'>,
                       rep_min_max<1, 2, DIGIT>,
                       seq<one<'1'>, DIGIT, DIGIT>,
                       seq<one<'2'>, range<'0', '4'>, DIGIT>,
                       seq<string<'2','5'>, range<'0','5'>>> {};
// clang-format on

struct ipv4_address
    : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {
};

struct h16 : rep_min_max<1, 4, HEXDIG> {
};

struct ls32 : sor<seq<h16, colon, h16>, ipv4_address> {
};

struct dcolon : two<':'> {
};

// clang-format off
struct ipv6_address : sor<seq<                                          rep<6, h16, colon>, ls32>,
                          seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                          seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>, 
                          seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                          seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                          seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                          seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};
// clang-format on

struct ip : sor<ipv4_address, ipv6_address> {
};

struct local_part : sor<dot_atom, quoted_string> {
};

struct dtext : ranges<33, 90, 94, 126> {
};

struct domain_literal : seq<opt<CFWS>,
                            one<'['>,
                            star<seq<opt<FWS>, dtext>>,
                            opt<FWS>,
                            one<']'>,
                            opt<CFWS>> {
};

struct domain : sor<dot_atom, domain_literal> {
};

struct addr_spec : seq<local_part, one<'@'>, domain> {
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
}

namespace RFC5321 {

struct Connection {
  Sock sock;

  std::string server_id;

  std::string ehlo_keyword;
  std::string ehlo_param;
  std::unordered_map<std::string, std::string> ehlo_params;

  std::string reply_code;

  Connection(int fd)
    : sock(fd, fd, Config::read_timeout, Config::write_timeout)
  {
  }
};

struct quoted_pair : seq<one<'\\'>, sor<VCHAR, WSP>> {
};

using dot = one<'.'>;
using colon = one<':'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, UTF8::non_ascii> {
};

struct u_ldh_str : plus<sor<ALPHA, DIGIT, UTF8::non_ascii, dash>> {
  // verify last char is a U_Let_dig
};

struct u_label : seq<u_let_dig, opt<u_ldh_str>> {
};

struct let_dig : sor<ALPHA, DIGIT> {
};

struct ldh_str : plus<sor<ALPHA, DIGIT, dash>> {
  // verify last char is a U_Let_dig
};

struct label : seq<let_dig, opt<ldh_str>> {
};

struct sub_domain : sor<label, u_label> {
};

struct domain : list<sub_domain, dot> {
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

struct IPv6_address_literal : seq<TAOCPP_PEGTL_ISTRING("IPv6:"), IPv6address> {
};

struct dcontent : ranges<33, 90, 94, 126> {
};

struct standardized_tag : ldh_str {
};

struct general_address_literal : seq<standardized_tag, colon, plus<dcontent>> {
};

// See rfc 5321 Section 4.1.3
struct address_literal : seq<one<'['>,
                             sor<IPv4_address_literal,
                                 IPv6_address_literal,
                                 general_address_literal>,
                             one<']'>> {
};

// textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

struct textstring : plus<sor<one<9>, range<32, 126>>> {
};

struct server_id : sor<domain, address_literal> {
};

// Greeting       = ( "220 " (Domain / address-literal) [ SP textstring ] CRLF )
//                  /
//                  ( "220-" (Domain / address-literal) [ SP textstring ] CRLF
//                 *( "220-" [ textstring ] CRLF )
//                    "220 " [ textstring ] CRLF )

struct greeting
    : sor<seq<TAOCPP_PEGTL_ISTRING("220 "),
              server_id,
              opt<seq<SP, textstring>>,
              CRLF>,
          seq<TAOCPP_PEGTL_ISTRING("220-"),
              server_id,
              opt<seq<SP, textstring>>,
              CRLF,
              star<seq<TAOCPP_PEGTL_ISTRING("220-"), opt<textstring>, CRLF>>,
              seq<TAOCPP_PEGTL_ISTRING("220 "), opt<textstring>, CRLF>>> {
};

// Reply-code     = %x32-35 %x30-35 %x30-39

struct reply_code
    : seq<range<0x32, 0x35>, range<0x30, 0x35>, range<0x30, 0x39>> {
};

// Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
//                   Reply-code [ SP textstring ] CRLF

struct reply_lines : seq<star<seq<reply_code, one<'-'>, opt<textstring>, CRLF>>,
                         seq<reply_code, opt<seq<SP, textstring>>, CRLF>> {
};

// ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
//                    ; string of any characters other than CR or LF

struct ehlo_greet : plus<sor<range<0, 9>, range<11, 12>, range<14, 127>>> {
};

// ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
//                  ; additional syntax of ehlo-params depends on
//                  ; ehlo-keyword

struct ehlo_keyword : seq<sor<ALPHA, DIGIT>, star<sor<ALPHA, DIGIT, dash>>> {
};

// ehlo-param     = 1*(%d33-126)
//                  ; any CHAR excluding <SP> and all
//                  ; control characters (US-ASCII 0-31 and 127
//                  ; inclusive)

struct ehlo_param : plus<range<33, 126>> {
};

// ehlo-line      = ehlo-keyword *( SP ehlo-param )
// with extra support for AUTH=

struct ehlo_line : seq<ehlo_keyword, star<seq<sor<SP, one<'='>>, ehlo_param>>> {
};

// ehlo-ok-rsp    = ( "250 " Domain [ SP ehlo-greet ] CRLF )
//                  /
//                  ( "250-" Domain [ SP ehlo-greet ] CRLF
//                 *( "250-" ehlo-line CRLF )
//                    "250 " ehlo-line CRLF )

struct ehlo_ok_rsp
    : sor<seq<TAOCPP_PEGTL_ISTRING("250 "),
              domain,
              opt<seq<SP, ehlo_greet>>,
              CRLF>,
          seq<seq<TAOCPP_PEGTL_ISTRING("250-"),
                  domain,
                  opt<seq<SP, ehlo_greet>>,
                  CRLF,
                  star<seq<TAOCPP_PEGTL_ISTRING("250-"), ehlo_line, CRLF>>,
                  seq<TAOCPP_PEGTL_ISTRING("250 "), ehlo_line, CRLF>>>> {
};

struct auth_login_username
    : seq<TAOCPP_PEGTL_STRING("334 VXNlcm5hbWU6"), CRLF> {
};

struct auth_login_password
    : seq<TAOCPP_PEGTL_STRING("334 UGFzc3dvcmQ6"), CRLF> {
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
    cnn.ehlo_param = in.string();
  }
};

template <>
struct action<ehlo_line> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    boost::to_upper(cnn.ehlo_keyword);
    cnn.ehlo_params[cnn.ehlo_keyword] = cnn.ehlo_param;
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
}

int conn(std::string const& node, std::string const& service)
{
  addrinfo* res = nullptr;
  auto gaierr = getaddrinfo(node.c_str(), service.c_str(), nullptr, &res);
  CHECK(gaierr == 0) << "getaddrinfo failed: " << gai_strerror(gaierr);

  for (auto r = res; r; r = r->ai_next) {
    auto addr = r->ai_addr;
    switch (addr->sa_family) {
    case AF_INET: {
      if (FLAGS_ip_6)
        break;

      auto in4 = reinterpret_cast<sockaddr_in*>(addr);

      int fd = socket(AF_INET, SOCK_STREAM, 0);
      PCHECK(fd >= 0) << "socket failed";
      if (connect(fd, addr, sizeof(*in4)) == 0) {
        freeaddrinfo(res);
        return fd;
      }
      PLOG(WARNING) << "connect failed for node==" << node
                    << ", service ==" << service;

      char str[INET_ADDRSTRLEN]{0};
      PCHECK(inet_ntop(AF_INET, &(in4->sin_addr), str, sizeof str));
      LOG(WARNING) << "connect failed for IP4==" << str
                   << ", port==" << ntohs(in4->sin_port);

      close(fd);
      break;
    }

    case AF_INET6: {
      if (FLAGS_ip_4)
        break;

      auto in6 = reinterpret_cast<sockaddr_in6*>(addr);

      int fd = socket(AF_INET6, SOCK_STREAM, 0);
      PCHECK(fd >= 0) << "socket failed";
      if (connect(fd, addr, sizeof(*in6)) == 0) {
        freeaddrinfo(res);
        return fd;
      }
      PLOG(WARNING) << "connect failed for node==" << node
                    << ", service ==" << service;

      char str[INET6_ADDRSTRLEN]{0};
      PCHECK(inet_ntop(AF_INET6, &(in6->sin6_addr), str, sizeof str));
      LOG(WARNING) << "connect failed for IP6==" << str
                   << ", port==" << ntohs(in6->sin6_port);

      close(fd);
      break;
    }

    default:
      LOG(FATAL) << "unknown address type: " << addr->sa_family;
      break;
    }
  }

  freeaddrinfo(res);
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

std::string base64(string_view s)
{
  using namespace boost::archive::iterators;

  typedef insert_linebreaks<base64_from_binary<transform_width<std::string::
                                                                   const_iterator,
                                                               6, 8>>,
                            72>
      it_base64_t;

  unsigned int writePaddChars = (3 - s.length() % 3) % 3;
  std::string b64(it_base64_t(s.begin()), it_base64_t(s.end()));
  b64.append(writePaddChars, '=');
  return b64;
}

namespace gflags {
// in case we didn't have one
}

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

void self_test()
{
  static RFC5321::Connection cnn(0);

  const char* greet_list[]{
      "220-mtaig-aak03.mx.aol.com ESMTP Internet Inbound\r\n"
      "220-AOL and its affiliated companies do not\r\n"
      "220-authorize the use of its proprietary computers and computer\r\n"
      "220-networks to accept, transmit, or distribute unsolicited bulk\r\n"
      "220-e-mail sent from the internet.\r\n"
      "220-Effective immediately:\r\n"
      "220-AOL may no longer accept connections from IP addresses\r\n"
      "220 which no do not have reverse-DNS (PTR records) assigned.\r\n"

  };

  for (auto i : greet_list) {
    memory_input<> in(i, i);
    if (!parse<RFC5321::greeting, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(ERROR) << "Error parsing greeting \"" << i << "\"";
    }
  }
}

int main(int argc, char* argv[])
{
  // self_test();

  const auto hostname = get_hostname();
  FLAGS_sender = hostname.c_str();

  const auto from = "♥@"s + hostname;
  FLAGS_from = from.c_str();

  const auto to = "♥@"s + hostname;
  FLAGS_to = to.c_str();

  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  Domain sender(FLAGS_sender);

  Domain receiver;
  if (!FLAGS_receiver.empty()) {
    receiver.set(FLAGS_receiver);
  }
  else {
    // parse FLAGS_to as addr_spec
    Mailbox mbx;
    memory_input<> in(FLAGS_to, "to");
    if (!parse<RFC5322::addr_spec, RFC5322::action>(in, mbx)) {
      LOG(ERROR) << "Error parsing address \"" << FLAGS_receiver << "\"";
    }

    LOG(INFO) << "mbx == " << mbx;

    // look up MX records for mbx.domain()
    using namespace DNS;
    Resolver res;

    // returns list of servers sorted by priority, low to high
    auto mxs = get_records<RR_type::MX>(res, mbx.domain().ascii());

    if (!mxs.empty())
      receiver.set(mxs[0]);
    else
      receiver = mbx.domain();
  }

  if (FLAGS_ip_4 && FLAGS_ip_6) {
    std::cerr << "Must use /some/ IP version.";
    return 1;
  }

  Eml eml;

  Now date;

  Pill red, blue;
  std::stringstream mid_str;
  mid_str << '<' << date.sec() << '.' << red << '.' << blue << '@'
          << sender.utf8() << '>';
  eml.add_hdr("Message-ID"s, mid_str.str());

  eml.add_hdr("Date"s, date.string());

  std::string rfc5322_from = FLAGS_from_name + " <" + FLAGS_from + ">";
  eml.add_hdr("From"s, rfc5322_from);

  std::string rfc5322_to = FLAGS_to_name + " <" + FLAGS_to + ">";
  eml.add_hdr("To"s, rfc5322_to);

  eml.add_hdr("Subject"s, FLAGS_subject);
  eml.add_hdr("Keywords"s, FLAGS_keywords);

  eml.add_hdr("MIME-Version"s, "1.0"s);
  eml.add_hdr("Content-Type"s, "text/plain; charset=\"UTF-8\""s);
  eml.add_hdr("Content-Transfer-Encoding", "8bit"s);

  boost::filesystem::path body_path("body.txt");
  auto body_sz = boost::filesystem::file_size(body_path);
  if (body_sz == 0) {
    std::cerr << "body.txt is empty\n";
    return 2;
  }

  boost::iostreams::mapped_file_source body(body_path);

  std::ifstream keyfs("private.key");
  std::string key(std::istreambuf_iterator<char>{keyfs}, {});

  OpenDKIM::Sign dks(key.c_str(), FLAGS_selector.c_str(), FLAGS_sender.c_str());

  eml.foreach_hdr([&dks](std::string const& name, std::string const& value) {
    auto header = name + ": "s + value;
    dks.header(header.c_str());
  });
  dks.eoh();
  dks.body(string_view(body.data(), body.size()));
  dks.eom();

  eml.add_hdr("DKIM-Signature"s, dks.getsighdr());

  auto fd = conn(receiver.ascii(), FLAGS_service);
  CHECK_NE(fd, -1);
  static RFC5321::Connection cnn(fd);

  istream_input<eol::crlf> in(cnn.sock.in(), Config::bfr_size, "session");

  try {
    CHECK((parse<RFC5321::greeting, RFC5321::action>(in, cnn)));

    LOG(INFO) << "> EHLO " << sender.utf8();
    cnn.sock.out() << "EHLO " << sender.utf8() << "\r\n" << std::flush;
    CHECK((parse<RFC5321::ehlo_ok_rsp, RFC5321::action>(in, cnn)));

    if (cnn.ehlo_params.find("STARTTLS") != cnn.ehlo_params.end()) {
      LOG(INFO) << "> STARTTLS";
      cnn.sock.out() << "STARTTLS\r\n" << std::flush;
      CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

      cnn.sock.starttls_client();

      LOG(INFO) << "> EHLO " << sender.utf8();
      cnn.sock.out() << "EHLO " << sender.utf8() << "\r\n" << std::flush;
      CHECK((parse<RFC5321::ehlo_ok_rsp, RFC5321::action>(in, cnn)));
    }

    if (cnn.server_id != receiver.ascii()) {
      LOG(INFO) << "server identifies as " << cnn.server_id;
    }

    bool ext_smtputf8
        = cnn.ehlo_params.find("SMTPUTF8") != cnn.ehlo_params.end();
    bool ext_8bitmime
        = cnn.ehlo_params.find("8BITMIME") != cnn.ehlo_params.end();

    auto max_msg_size = 0u;
    bool ext_size = cnn.ehlo_params.find("SIZE") != cnn.ehlo_params.end();
    if (ext_size) {
      max_msg_size = strtoul(cnn.ehlo_params["SIZE"].c_str(), nullptr, 0);
    }
    if (!max_msg_size) {
      max_msg_size = Config::max_msg_size;
    }

    if ((!FLAGS_username.empty()) && (!FLAGS_password.empty())) {
      if (cnn.ehlo_params.find("AUTH") != cnn.ehlo_params.end()) {
        LOG(INFO) << "> AUTH";
        cnn.sock.out() << "AUTH LOGIN\r\n" << std::flush;
        CHECK((parse<RFC5321::auth_login_username>(in)));
        cnn.sock.out() << base64(FLAGS_username) << "\r\n" << std::flush;
        CHECK((parse<RFC5321::auth_login_password>(in)));
        cnn.sock.out() << base64(FLAGS_password) << "\r\n" << std::flush;
        CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
      }
      else {
        LOG(WARNING) << "server doesn't support AUTH";
      }
    }

    std::string param;
    if (ext_8bitmime) {
      param += " BODY=8BITMIME";
    }
    else {
      // check and perhaps convert body
    }

    if (ext_smtputf8) {
      param += " SMTPUTF8";
    }
    else {
      // check and perhaps convert headers
    }

    LOG(INFO) << "> MAIL FROM:<" << FLAGS_from << '>' << param;
    cnn.sock.out() << "MAIL FROM:<" << FLAGS_from << '>' << param << "\r\n"
                   << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

    LOG(INFO) << "> RCPT TO:<" << FLAGS_to;
    cnn.sock.out() << "RCPT TO:<" << FLAGS_to << ">\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

    if (FLAGS_use_chunking
        && (cnn.ehlo_params.find("CHUNKING") != cnn.ehlo_params.end())) {
      std::stringstream hdr_stream;
      hdr_stream << eml;
      auto hdr_str = hdr_stream.str();

      auto total_size = hdr_str.size() + body.size();
      if (total_size > max_msg_size) {
        std::cerr << "message size " << total_size << " exceeds size limit of "
                  << max_msg_size;
        LOG(INFO) << "> QUIT";
        cnn.sock.out() << "QUIT\r\n" << std::flush;
        CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
      }

      std::stringstream bdat_stream;
      bdat_stream << "BDAT " << total_size << " LAST";
      LOG(INFO) << "> " << bdat_stream.str();

      cnn.sock.out() << bdat_stream.str() << "\r\n" << std::flush;
      cnn.sock.out().write(hdr_str.data(), hdr_str.size());
      CHECK(cnn.sock.out().good());
      cnn.sock.out().write(body.data(), body.size());
      CHECK(cnn.sock.out().good());
      cnn.sock.out() << std::flush;
      CHECK(cnn.sock.out().good());

      CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    }
    else {
      LOG(INFO) << "> DATA";
      cnn.sock.out() << "DATA\r\n" << std::flush;
      CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));

      cnn.sock.out() << eml;

      imemstream isbody(body.data(), body.size());
      std::string line;
      while (std::getline(isbody, line)) {
        if (line.length() && (line.at(0) == '.')) {
          cnn.sock.out() << '.';
        }
        cnn.sock.out() << line;
        if (line.back() != '\r')
          cnn.sock.out() << '\r';
        cnn.sock.out() << '\n';
      }

      // Done!
      cnn.sock.out() << ".\r\n" << std::flush;
      CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
    }

    LOG(INFO) << "> QUIT";
    cnn.sock.out() << "QUIT\r\n" << std::flush;
    CHECK((parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)));
  }
  catch (parse_error const& e) {
    std::cerr << "parse_error == " << e.what();
    return 1;
  }
  catch (std::exception const& e) {
    std::cerr << e.what();
    return 1;
  }
}

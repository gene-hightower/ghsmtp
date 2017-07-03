#include "Sock.hpp"

#include <iostream>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <experimental/string_view>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;
using namespace tao::pegtl::alphabet;

using namespace std::string_literals;

using std::experimental::string_view;

namespace Config {
constexpr std::streamsize bfr_size = 4 * 1024;

constexpr auto read_timeout = std::chrono::seconds(30);
constexpr auto write_timeout = std::chrono::minutes(3);
}

namespace RFC5321 {

struct Connection {
  Sock sock;

  Connection(int fd)
    : sock(fd, fd, Config::read_timeout, Config::write_timeout)
  {
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

struct u_let_dig : sor<ALPHA, DIGIT, UTF8_non_ascii> {
};

struct u_ldh_str : plus<sor<ALPHA, DIGIT, UTF8_non_ascii, dash>> {
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
                         seq<reply_code, SP, opt<textstring>, CRLF>> {
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

struct ehlo_line : seq<ehlo_keyword, star<seq<SP, ehlo_param>>> {
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

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<greeting> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    LOG(INFO) << "greeting: " << in.string();
  }
};

template <>
struct action<ehlo_ok_rsp> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    LOG(INFO) << "ehlo_ok_rsp: " << in.string();
  }
};

template <>
struct action<reply_lines> {
  template <typename Input>
  static void apply(Input const& in, Connection& cnn)
  {
    LOG(INFO) << "reply_lines: " << in.string();
  }
};
}

void greeting() {}

int conn(char const* node, char const* service)
{
  addrinfo* res = nullptr;
  auto gaierr = getaddrinfo(node, service, nullptr, &res);
  CHECK(gaierr == 0) << "getaddrinfo failed: " << gai_strerror(gaierr);

  for (auto r = res; r; r = r->ai_next) {
    auto addr = r->ai_addr;
    switch (addr->sa_family) {
    case AF_INET: {
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

int main(int argc, char const* argv[])
{
  static RFC5321::Connection cnn(conn("localhost", "smtp-test"));

  istream_input<eol::crlf> in(cnn.sock.in(), Config::bfr_size, "session");

  try {
    if (!parse<RFC5321::greeting, RFC5321::action>(in, cnn)) {
      if (cnn.sock.timed_out()) {
        std::cerr << "timed out waiting for greeting\n";
      }
      else {
        std::cerr << "syntax error from parser\n";
      }
      return 1;
    }
    LOG(INFO) << "greeting parse success";

    cnn.sock.out() << "EHLO digilicious.com\r\n" << std::flush;

    if (!parse<RFC5321::ehlo_ok_rsp, RFC5321::action>(in, cnn)) {
      if (cnn.sock.timed_out()) {
        std::cerr << "timed out waiting for ehlo_ok_rsp\n";
      }
      else {
        std::cerr << "syntax error from parser\n";
      }
      return 1;
    }
    LOG(INFO) << "ehlo_ok_rsp parse success";

    cnn.sock.out() << "QUIT\r\n" << std::flush;

    if (!parse<RFC5321::reply_lines, RFC5321::action>(in, cnn)) {
      if (cnn.sock.timed_out()) {
        std::cerr << "timed out waiting for quit reply\n";
      }
      else {
        std::cerr << "syntax error from parser\n";
      }
      return 1;
    }
    LOG(INFO) << "reply_lines parse success";
  }
  catch (parse_error const& e) {
    std::cerr << e.what();
    return 1;
  }
}
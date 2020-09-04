#include "rewrite.hpp"

#include "OpenARC.hpp"
#include "OpenDKIM.hpp"
#include "OpenDMARC.hpp"
#include "esc.hpp"
#include "imemstream.hpp"

#include <cstring>
#include <map>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

auto constexpr ARC_Authentication_Results = "ARC-Authentication-Results";
auto constexpr ARC_Message_Signature      = "ARC-Message-Signature";
auto constexpr ARC_Seal                   = "ARC-Seal";

auto constexpr Authentication_Results = "Authentication-Results";
auto constexpr DKIM_Signature         = "DKIM-Signature";
auto constexpr Delivered_To           = "Delivered-To";
auto constexpr Received_SPF           = "Received-SPF";
auto constexpr Return_Path            = "Return-Path";

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

namespace RFC5322 {

using dot   = one<'.'>;
using colon = one<':'>;

// clang-format off

struct UTF8_tail        : range<'\x80', '\xBF'> {};

struct UTF8_1           : range<0x00, 0x7F> {};

struct UTF8_2           : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3           : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                              seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                              seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                              seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4           : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
                              seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
                              seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

struct UTF8_non_ascii   : sor<UTF8_2, UTF8_3, UTF8_4> {};

struct VUCHAR           : sor<VCHAR, UTF8_non_ascii> {};

/////////////////////////////////////////////////////////////////////////////

struct ftext            : ranges<33, 57, 59, 126> {};

struct field_name       : plus<ftext> {};

struct FWS              : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// *([FWS] VCHAR) *WSP
struct field_value      : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {};

struct field            : seq<field_name, one<':'>, field_value, eol> {};

struct fields           : star<field> {};

struct body             : until<eof> {};

struct message          : seq<fields, opt<seq<eol, body>>, eof> {};

/////////////////////////////////////////////////////////////////////////////

// <https://tools.ietf.org/html/rfc2047>

//   especials = "(" / ")" / "<" / ">" / "@" / "," / ";" / ":" / "
//               <"> / "/" / "[" / "]" / "?" / "." / "="

//   token = 1*<Any CHAR except SPACE, CTLs, and especials>

struct tchar47          : ranges<        // NUL..' '
                                 33, 33, // !
                              // 34, 34, // "
                                 35, 39, // #$%&'
                              // 40, 41, // ()
                                 42, 43, // *+
                              // 44, 44, // ,
                                 45, 45, // -
                              // 46, 47, // ./
                                 48, 57, // 0123456789
                              // 58, 64, // ;:<=>?@
                                 65, 90, // A..Z
                              // 91, 91, // [
                                 92, 92, // '\\'
                              // 93, 93, // ]
                                 94, 126 // ^_` a..z {|}~
                              // 127,127 // DEL
                                > {};

struct token47           : plus<tchar47> {};

struct charset           : token47 {};
struct encoding          : token47 {};

//   encoded-text = 1*<Any printable ASCII character other than "?"
//                     or SPACE>

struct echar            : ranges<        // NUL..' '
                                 33, 62, // !..>
                              // 63, 63, // ?
                                 64, 126 // @A..Z[\]^_` a..z {|}~
                              // 127,127 // DEL
                                > {};

struct encoded_text     : plus<echar> {};

//   encoded-word = "=?" charset "?" encoding "?" encoded-text "?="

// leading opt<FWS> is not in RFC 2047

struct encoded_word_book: seq<string<'=', '?'>,
                              charset, string<'?'>,
                              encoding, string<'?'>,
                              encoded_text,
                              string<'=', '?'>
                              > {};

struct encoded_word     : seq<opt<FWS>, encoded_word_book> {};

/////////////////////////////////////////////////////////////////////////////

// Comments are recursive, so the forward decl
struct comment;

struct quoted_pair      : seq<one<'\\'>, sor<VUCHAR, WSP>> {};

// ctext is ASCII not '(' or ')' or '\\'
struct ctext            : sor<ranges<33, 39, 42, 91, 93, 126>, UTF8_non_ascii> {};

struct ccontent         : sor<ctext, quoted_pair, comment, encoded_word> {};

// from <https://tools.ietf.org/html/rfc2047>
// comment = "(" *(ctext / quoted-pair / comment / encoded-word) ")"

struct comment          : seq<one<'('>,
                              star<seq<opt<FWS>, ccontent>>,
                              opt<FWS>,
                              one<')'>
                              > {};

struct CFWS             : sor<seq<plus<seq<opt<FWS>, comment>, opt<FWS>>>,
                              FWS> {};

struct qtext            : sor<one<33>, ranges<35, 91, 93, 126>, UTF8_non_ascii> {};

struct qcontent         : sor<qtext, quoted_pair> {};

// Corrected in RFC-5322, errata ID: 3135 <https://www.rfc-editor.org/errata/eid3135>
struct quoted_string    : seq<opt<CFWS>,
                              DQUOTE,
                              sor<seq<star<seq<opt<FWS>, qcontent>>, opt<FWS>>, FWS>,
                              DQUOTE,
                              opt<CFWS>
                              > {};

struct atext            : sor<ALPHA, DIGIT,
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

struct atom             : seq<opt<CFWS>, plus<atext>, opt<CFWS>> {};

struct dot_atom_text    : list<plus<atext>, dot> {};

struct dot_atom         : seq<opt<CFWS>, dot_atom_text, opt<CFWS>> {};

struct word             : sor<atom, quoted_string> {};

// struct phrase        : plus<sor<encoded_word, word>> {};

struct dec_octet        : sor<seq<string<'2','5'>, range<'0','5'>>,
                              seq<one<'2'>, range<'0','4'>, DIGIT>,
                              seq<range<'0', '1'>, rep<2, DIGIT>>,
                              rep_min_max<1, 2, DIGIT>> {};

struct ipv4_address     : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {};

struct h16              : rep_min_max<1, 4, HEXDIG> {};

struct ls32             : sor<seq<h16, colon, h16>, ipv4_address> {};

struct dcolon           : two<':'> {};

struct ipv6_address     : sor<seq<                                          rep<6, h16, colon>, ls32>,
                              seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                              seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>, 
                              seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                              seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                              seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                              seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                              seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                              seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};

struct ip               : sor<ipv4_address, ipv6_address> {};

struct local_part       : sor<dot_atom, quoted_string> {};

struct dtext            : ranges<33, 90, 94, 126> {};

struct domain_literal   : seq<opt<CFWS>,
                              one<'['>,
                              star<seq<opt<FWS>, dtext>>,
                              opt<FWS>,
                              one<']'>,
                              opt<CFWS>> {};

struct domain           : sor<dot_atom, domain_literal> {};

struct addr_spec        : seq<local_part, one<'@'>, domain> {};

struct result           : sor<TAO_PEGTL_ISTRING("Pass"),
                              TAO_PEGTL_ISTRING("Fail"),
                              TAO_PEGTL_ISTRING("SoftFail"),
                              TAO_PEGTL_ISTRING("Neutral"),
                              TAO_PEGTL_ISTRING("None"),
                              TAO_PEGTL_ISTRING("TempError"),
                              TAO_PEGTL_ISTRING("PermError")> {};

struct spf_key          : sor<TAO_PEGTL_ISTRING("client-ip"),
                              TAO_PEGTL_ISTRING("envelope-from"),
                              TAO_PEGTL_ISTRING("helo"),
                              TAO_PEGTL_ISTRING("problem"),
                              TAO_PEGTL_ISTRING("receiver"),
                              TAO_PEGTL_ISTRING("identity"),
                              TAO_PEGTL_ISTRING("mechanism")> {};

// This value syntax (allowing addr_spec) is not in accordance with RFC
// 7208 (or 4408) but is what is effectivly used by libspf2 1.2.10 and
// before.

struct spf_value        : sor<ip, addr_spec, dot_atom, quoted_string> {};

struct spf_kv_pair      : seq<spf_key, opt<CFWS>, one<'='>, spf_value> {};

struct spf_kv_list      : seq<spf_kv_pair,
                              star<seq<one<';'>, opt<CFWS>, spf_kv_pair>>,
                              opt<one<';'>>> {};

struct spf_header       : seq<opt<CFWS>,
                              result,
                              opt<seq<FWS, comment>>,
                              opt<seq<FWS, spf_kv_list>>> {};

struct received_spf     : seq<TAO_PEGTL_ISTRING("Received-SPF:"),
                              spf_header,
                              eof> {};
// clang-format on

struct header {
  header(std::string_view n, std::string_view v)
    : name(n)
    , value(v)
  {
  }

  std::string as_string() const { return fmt::format("{}:{}", name, value); }

  bool operator==(std::string_view n) const { return name == n; }

  std::string_view name;
  std::string_view value;
};

struct ci_less {
  bool operator()(std::string const& lhs, std::string const& rhs) const
  {
    // strcasecmp(3) is POSIX, FIXME: should force C locale
    return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
  }
};

struct message_parsed {
  bool parse(std::string_view msg);

  std::string as_string() const;

  std::vector<header> headers;

  std::string_view body;

  std::string_view field_name;
  std::string_view field_value;

  // SPF
  std::string spf_result;

  std::string spf_key;
  std::string spf_value;

  std::vector<std::pair<std::string, std::string>> spf_kv_list;

  std::map<std::string, std::string, ci_less> spf_info;

  // New Authentication_Results field
  std::string ar_str;
};

namespace {
template <typename Input>
std::string_view make_view(Input const& in)
{
  return std::string_view(in.begin(), std::distance(in.begin(), in.end()));
}
} // namespace

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<field_name> {
  template <typename Input>
  static void apply(Input const& in, message_parsed& msg)
  {
    msg.field_name = make_view(in);
  }
};

template <>
struct action<field_value> {
  template <typename Input>
  static void apply(Input const& in, message_parsed& msg)
  {
    msg.field_value = make_view(in);
  }
};

template <>
struct action<field> {
  template <typename Input>
  static void apply(Input const& in, message_parsed& msg)
  {
    msg.headers.emplace_back(header(msg.field_name, msg.field_value));
  }
};

template <>
struct action<body> {
  template <typename Input>
  static void apply(Input const& in, message_parsed& msg)
  {
    msg.body = make_view(in);
  }
};

/////////////////////////////////////////////////////////////////////////////

template <>
struct action<result> {
  template <typename Input>
  static void apply(const Input& in, message_parsed& msg)
  {
    msg.spf_result = std::move(in.string());
    boost::to_lower(msg.spf_result);
  }
};

template <>
struct action<spf_key> {
  template <typename Input>
  static void apply(const Input& in, message_parsed& msg)
  {
    msg.spf_key = std::move(in.string());
  }
};

template <>
struct action<spf_value> {
  template <typename Input>
  static void apply(const Input& in, message_parsed& msg)
  {
    msg.spf_value = std::move(in.string());
    boost::trim(msg.spf_value);
  }
};

template <>
struct action<spf_kv_pair> {
  template <typename Input>
  static void apply(const Input& in, message_parsed& msg)
  {
    msg.spf_kv_list.emplace_back(msg.spf_key, msg.spf_value);
    msg.spf_key.clear();
    msg.spf_value.clear();
  }
};

template <>
struct action<spf_kv_list> {
  static void apply0(message_parsed& msg)
  {
    for (auto kvp : msg.spf_kv_list) {
      CHECK(!msg.spf_info.contains(kvp.first))
          << "dup: " << kvp.first << " = " << kvp.second;
      msg.spf_info[kvp.first] = kvp.second;
    }
  }
};

bool message_parsed::parse(std::string_view input)
{
  auto in{memory_input<>(input.data(), input.size(), "message")};
  return tao::pegtl::parse<RFC5322::message, RFC5322::action>(in, *this);
}

std::string message_parsed::as_string() const
{
  fmt::memory_buffer bfr;

  for (auto const h : headers)
    fmt::format_to(bfr, "{}\r\n", h.as_string());

  if (!body.empty())
    fmt::format_to(bfr, "\r\n{}", body);

  return fmt::to_string(bfr);
}

} // namespace RFC5322

static void do_arc(char const* domain, RFC5322::message_parsed& msg)
{
  CHECK(!msg.headers.empty());

  for (auto header : msg.headers) {
    // clang-format off
    if (header == ARC_Seal ||
        header == ARC_Message_Signature ||
        header == ARC_Authentication_Results ||
        header == Received_SPF ||
        header == DKIM_Signature ||
        header == Authentication_Results)
      LOG(INFO) << '\n' << header.as_string() << '\n';
    // clang-format on
  }

  std::string spf_info_client_ip;

  for (auto header : msg.headers) {
    if (header == Received_SPF) {
      auto const h = header.as_string();

      auto in{memory_input<>(h.data(), h.length(), "received_spf")};
      if (tao::pegtl::parse<RFC5322::received_spf, RFC5322::action>(in, msg)) {
        if (auto const ip = msg.spf_info.find("client-ip");
            ip != msg.spf_info.end()) {
          spf_info_client_ip = ip->second;
          LOG(INFO) << "client-ip == " << spf_info_client_ip;
        }
        break; // take just the 1st that parses
      }
      LOG(WARNING) << "failed to parse " << Received_SPF;
    }
  }

  for (auto header : msg.headers) {
    if (header == Authentication_Results) {
      // LOG(INFO) << header.as_string();
      // parse header.value
      // break; // take just the 1st
    }
  }

  OpenDKIM::verify dkv;

  OpenARC::verify arv;

  for (auto header : msg.headers) {
    auto const hdr_str = fmt::format("{}:{}", header.name, header.value);
    // LOG(INFO) << "header «" << hdr_str << "»";
    arv.header(hdr_str);
    dkv.header(hdr_str);
  }
  dkv.eoh();
  arv.eoh();

  // LOG(INFO) << "body «" << msg.body << "»";
  arv.body(msg.body);
  dkv.body(msg.body);

  arv.eom();
  dkv.eom();

  // Build up Authentication-Results header
  fmt::memory_buffer bfr;
  fmt::format_to(bfr, " {};\r\n", domain);

  for (auto header : msg.headers) {
    if (header == Received_SPF) {
      auto v = std::string{header.value.data(), header.value.length()};
      boost::trim(v);
      fmt::format_to(bfr, "       spf={}\r\n", v);
    }
  }

  OpenDMARC::policy dmp;
  if (!spf_info_client_ip.empty()) {
    LOG(INFO) << "OpenDMARC::Policy::init(" << spf_info_client_ip << ")";
    dmp.connect(spf_info_client_ip.c_str());
  }

  // Get RFC5322.From

  if (auto hdr = std::find(begin(msg.headers), end(msg.headers), "From");
      hdr != end(msg.headers)) {
    auto const from = std::string{hdr->value.data(), hdr->value.length()};
    LOG(INFO) << "RFC5322.From: == " << from;
    dmp.store_from_domain(from.c_str());
  }
  else {
    LOG(ERROR) << "no From: header";
    dmp.store_from_domain("unknown.domain");
  }

  dkv.foreach_sig([&dmp, &bfr](char const* domain, bool passed) {
    auto const human_result = (passed ? "pass" : "fail");
    LOG(INFO) << "DKIM check for " << domain << " " << human_result;

    int const result = passed ? DMARC_POLICY_DKIM_OUTCOME_PASS
                              : DMARC_POLICY_DKIM_OUTCOME_FAIL;

    dmp.store_dkim(domain, result, human_result);

    fmt::format_to(bfr, "       dkim={}\r\n", human_result);
  });

  LOG(INFO) << "ARC status  == " << arv.chain_status_str();
  LOG(INFO) << "ARC custody == " << arv.chain_custody_str();

  if ("fail"s == arv.chain_status_str()) {
    LOG(INFO) << "existing failed ARC set, doing nothing more";
    return;
  }

  msg.ar_str = fmt::to_string(bfr);

  auto const ar = RFC5322::header(Authentication_Results, msg.ar_str);

  LOG(INFO) << ar.as_string();

  if (msg.headers[0] == Return_Path || msg.headers[0] == Delivered_To) {
    msg.headers[0] = ar;
  }
  else {
    msg.headers.insert(msg.headers.begin(), ar);
  }

  /*
  ARC_HDRFIELD* seal = nullptr;

  auto const priv_path = "ghsmtp.private";
  CHECK(fs::exists(priv_path));
  boost::iostreams::mapped_file_source priv;
  priv.open(priv_path);

  arc.seal(&seal, domain, "arc", dom, nullptr, 0, nullptr);

  if (seal) {
    auto const nam = OpenARC::hdr::name(seal);
    auto const val = OpenARC::hdr::value(seal);
    LOG(INFO) << nam << ": " << val;
  }
  else {
    LOG(INFO) << "Can't generate seal";
  }
  */
}

std::optional<std::string> rewrite(char const* domain, std::string_view input)
{
  RFC5322::message_parsed msg;

  if (!msg.parse(input)) {
    LOG(WARNING) << "failed to parse message";
    return {};
  }

  do_arc(domain, msg);

  return msg.as_string();
}

// What you get where:

// RFC5321.HELO/.EHLO domain
// RFC5321.MailFrom   mailbox
// RFC5322.From       mailbox-list

#include "message.hpp"

#include "Mailbox.hpp"
#include "OpenARC.hpp"
#include "OpenDKIM.hpp"
#include "OpenDMARC.hpp"
#include "esc.hpp"
#include "fs.hpp"
#include "iequal.hpp"
#include "imemstream.hpp"

#include <cstring>
#include <map>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using std::begin;
using std::end;

// DKIM key "selector"
auto constexpr selector = "ghsmtp";

// RFC-5322 header names
auto constexpr ARC_Authentication_Results = "ARC-Authentication-Results";
auto constexpr ARC_Message_Signature      = "ARC-Message-Signature";
auto constexpr ARC_Seal                   = "ARC-Seal";

auto constexpr Authentication_Results = "Authentication-Results";
auto constexpr DKIM_Signature         = "DKIM-Signature";
auto constexpr Delivered_To           = "Delivered-To";
auto constexpr From                   = "From";
auto constexpr Received_SPF           = "Received-SPF";
auto constexpr Reply_To               = "Reply-To";
auto constexpr Return_Path            = "Return-Path";

// MIME headers
auto constexpr Content_Type = "Content-Type";
auto constexpr MIME_Version = "MIME-Version";

// SPF Results
auto constexpr Pass      = "Pass";
auto constexpr Fail      = "Fail";
auto constexpr SoftFail  = "SoftFail";
auto constexpr Neutral   = "Neutral";
auto constexpr None      = "None";
auto constexpr TempError = "TempError";
auto constexpr PermError = "PermError";

// SPF keys
auto constexpr client_ip     = "client-ip";
auto constexpr envelope_from = "envelope-from";
auto constexpr problem       = "problem";
auto constexpr receiver      = "receiver";
auto constexpr identity      = "identity";
auto constexpr mechanism     = "mechanism";
// auto constexpr helo       = "helo"; // both key and value

// SPF identities
auto constexpr helo     = "helo";
auto constexpr mailfrom = "mailfrom";

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

static std::string make_string(std::string_view v)
{
  return std::string(v.begin(),
                     static_cast<size_t>(std::distance(v.begin(), v.end())));
}

static std::string_view trim(std::string_view v)
{
  auto constexpr WS = " \t";
  v.remove_prefix(std::min(v.find_first_not_of(WS), v.size()));
  v.remove_suffix(std::min(v.size() - v.find_last_not_of(WS) - 1, v.size()));
  return v;
}

template <typename Input>
static std::string_view make_view(Input const& in)
{
  return std::string_view(in.begin(), std::distance(in.begin(), in.end()));
}

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

//.............................................................................

struct ftext            : ranges<33, 57, 59, 126> {};

struct field_name       : plus<ftext> {};

struct FWS              : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// *([FWS] VCHAR) *WSP
struct field_value      : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {};

struct field            : seq<field_name, one<':'>, field_value, eol> {};

struct raw_field        : seq<field_name, one<':'>, field_value, eof> {};

struct fields           : star<field> {};

struct body             : until<eof> {};

struct message          : seq<fields, opt<seq<eol, body>>, eof> {};

//.............................................................................

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

//.............................................................................

// Comments are recursive, hence the forward declaration:
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

struct phrase          : plus<sor<encoded_word, word>> {};

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

// This addr_spec should be exactly the same as RFC5321 Mailbox, but it's not.

struct addr_spec        : seq<local_part, one<'@'>, domain> {};

struct addr_spec_only   : seq<addr_spec, eof> {};

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

struct spf_header_only  : seq<spf_header, eof> {};

//.............................................................................

struct display_name     : phrase {};

struct angle_addr       : seq<opt<CFWS>, one<'<'>, addr_spec, one<'>'>, opt<CFWS>> {};

struct name_addr        : seq<opt<display_name>, angle_addr> {};

struct mailbox          : sor<name_addr, addr_spec> {};

struct obs_mbox_list    : seq<star<seq<opt<CFWS>, one<','>>>,
                              mailbox,
                              star<one<','>, opt<sor<mailbox, CFWS>>>
                              > {};

struct mailbox_list     : sor<list<mailbox, one<','>>,
                              obs_mbox_list
                              > {};

// struct from          : seq<TAO_PEGTL_ISTRING("From:"),
//                            mailbox_list
//                            > {};

struct mailbox_list_only: seq<mailbox_list, eof> {};

//.............................................................................

// struct authres_header_field: seq<TAO_PEGTL_ISTRING("Authentication-Results:"),
//                                  authres_payload> {};

//.............................................................................

// clang-format on

template <typename Rule>
struct msg_action : nothing<Rule> {
};

template <>
struct msg_action<field_name> {
  template <typename Input>
  static void apply(Input const& in, ::message::parsed& msg)
  {
    msg.field_name = make_view(in);
  }
};

template <>
struct msg_action<field_value> {
  template <typename Input>
  static void apply(Input const& in, ::message::parsed& msg)
  {
    msg.field_value = make_view(in);
  }
};

template <>
struct msg_action<field> {
  template <typename Input>
  static void apply(Input const& in, ::message::parsed& msg)
  {
    msg.headers.emplace_back(
        ::message::header(msg.field_name, msg.field_value));
  }
};

template <>
struct msg_action<raw_field> {
  template <typename Input>
  static void apply(Input const& in, ::message::parsed& msg)
  {
    msg.headers.emplace_back(
        ::message::header(msg.field_name, msg.field_value));
  }
};

template <>
struct msg_action<body> {
  template <typename Input>
  static void apply(Input const& in, ::message::parsed& msg)
  {
    msg.body = make_view(in);
  }
};

//.............................................................................

struct received_spf_parsed {
  bool parse(std::string_view input);

  std::string_view result;

  std::string_view key;
  std::string_view value;

  std::vector<std::pair<std::string_view, std::string_view>> kv_list;
  std::map<std::string_view, std::string_view, ci_less>      kv_map;
};

template <typename Rule>
struct spf_action : nothing<Rule> {
};

template <>
struct spf_action<result> {
  template <typename Input>
  static void apply(const Input& in, received_spf_parsed& spf)
  {
    spf.result = make_view(in);
  }
};

template <>
struct spf_action<spf_key> {
  template <typename Input>
  static void apply(const Input& in, received_spf_parsed& spf)
  {
    spf.key = make_view(in);
  }
};

template <>
struct spf_action<spf_value> {
  template <typename Input>
  static void apply(const Input& in, received_spf_parsed& spf)
  {
    // RFC5322 syntax is full of optional WS, so we trim
    spf.value = trim(make_view(in));
  }
};

template <>
struct spf_action<spf_kv_pair> {
  template <typename Input>
  static void apply(const Input& in, received_spf_parsed& spf)
  {
    spf.kv_list.emplace_back(spf.key, spf.value);
    spf.key = spf.value = "";
  }
};

template <>
struct spf_action<spf_kv_list> {
  static void apply0(received_spf_parsed& spf)
  {
    for (auto kvp : spf.kv_list) {
      if (spf.kv_map.contains(kvp.first)) {
        LOG(WARNING) << "dup key: " << kvp.first << "=" << kvp.second;
        LOG(WARNING) << "    and: " << kvp.first << "="
                     << spf.kv_map[kvp.first];
      }
      spf.kv_map[kvp.first] = kvp.second;
    }
  }
};

bool received_spf_parsed::parse(std::string_view input)
{
  auto in{memory_input<>(input.data(), input.size(), "spf_header")};
  return tao::pegtl::parse<spf_header_only, spf_action>(in, *this);
}

//.............................................................................

// Parse a grammar and extract each addr_spec

template <typename Rule>
struct addr_specs_action : nothing<Rule> {
};

template <>
struct addr_specs_action<addr_spec> {
  template <typename Input>
  static void apply(Input const& in, std::vector<std::string>& addr_specs)
  {
    addr_specs.push_back(in.string());
  }
};

} // namespace RFC5322

// Map SPF result string to DMARC policy code.

// FIXME: This mapping needs to be examined and confirmed, no time now.

static int result_to_pol(std::string_view result)
{
  // clang-format off
  if (iequal(result, Pass))      return DMARC_POLICY_SPF_OUTCOME_PASS;
  if (iequal(result, Fail))      return DMARC_POLICY_SPF_OUTCOME_FAIL;
  if (iequal(result, SoftFail))  return DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
  if (iequal(result, Neutral))   return DMARC_POLICY_SPF_OUTCOME_NONE;
  if (iequal(result, None))      return DMARC_POLICY_SPF_OUTCOME_NONE;
  if (iequal(result, TempError)) return DMARC_POLICY_SPF_OUTCOME_NONE;
  if (iequal(result, PermError)) return DMARC_POLICY_SPF_OUTCOME_NONE;
  LOG(WARNING) << "unknown SPF result: \"" << result << "\"";
  return DMARC_POLICY_SPF_OUTCOME_NONE;
  // clang-format on
}

static void spf_result_to_dmarc(OpenDMARC::policy&            dmp,
                                RFC5322::received_spf_parsed& spf)
{
  if (spf.kv_map.contains(problem)) {
    LOG(WARNING) << "SPF problem: " << spf.kv_map[problem];
  }

  auto const spf_pol = result_to_pol(spf.result);

  std::string spf_dom;

  int spf_origin;

  if (spf.kv_map.contains(identity)) {
    if (iequal(spf.kv_map[identity], mailfrom)) {
      if (spf.kv_map.contains(envelope_from)) {
        if (Mailbox::validate(spf.kv_map[envelope_from])) {
          Mailbox mbx(spf.kv_map[envelope_from]);
          spf_dom    = mbx.domain().ascii();
          spf_origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;

          auto const human_result = fmt::format(
              "{}, explicit origin mail from, mailbox {}", spf.result, mbx);
          LOG(INFO) << "SPF result " << human_result;
          dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin,
                        human_result.c_str());
          return;
        }
        else {
          LOG(WARNING) << "invalid mailbox in envelope-from: "
                       << spf.kv_map[envelope_from];
        }
      }
      else {
        LOG(WARNING)
            << "identity checked was mail from, but no envelope_from key";
      }
    }
    else if (iequal(spf.kv_map[identity], helo)) {
      if (spf.kv_map.contains(helo)) {
        if (Domain::validate(spf.kv_map[helo])) {
          Domain dom(spf.kv_map[helo]);
          spf_dom    = dom.ascii();
          spf_origin = DMARC_POLICY_SPF_ORIGIN_HELO;

          auto const human_result = fmt::format(
              "{}, explicit origin hello, domain {}", spf.result, dom);
          LOG(INFO) << "SPF result " << human_result;
          dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin,
                        human_result.c_str());
          return;
        }
        else {
          LOG(WARNING) << "invalid domain in helo: " << spf.kv_map[helo];
        }
      }
      else {
        LOG(WARNING) << "identity checked was helo, but no helo key";
      }
    }
    else {
      LOG(WARNING) << "unknown identity " << spf.kv_map[identity];
    }
  }
  else {
    LOG(INFO) << "no explicit tag for which identity was checked";
  }

  if (spf.kv_map.contains(envelope_from)) {
    auto const efrom = spf.kv_map[envelope_from];

    if (efrom == "<>") {
      if (spf.kv_map.contains(helo)) {
        if (Domain::validate(spf.kv_map[helo])) {
          Domain dom(spf.kv_map[helo]);
          spf_dom    = dom.ascii();
          spf_origin = DMARC_POLICY_SPF_ORIGIN_HELO;

          auto const human_result = fmt::format(
              "{}, RFC-5321.FROM is <>, implicit origin hello, domain {}",
              spf.result, dom);
          LOG(INFO) << "SPF result " << human_result;
          dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin,
                        human_result.c_str());
          return;
        }
        else {
          LOG(WARNING) << "RFC-5321.FROM is <> but helo is invalid domain: "
                       << spf.kv_map[helo];
        }
      }
      else {
        LOG(WARNING) << "envelope-from is <> but no helo key";
      }
    }
    else if (Mailbox::validate(efrom)) {
      // We're good to go
      Mailbox mbx(efrom);
      spf_dom    = mbx.domain().ascii();
      spf_origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;

      auto const human_result = fmt::format(
          "{}, implicit origin mail from, mailbox {}", spf.result, mbx);
      LOG(INFO) << "SPF result " << human_result;
      dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin, human_result.c_str());
      return;
    }
    else {
      LOG(WARNING) << "envelope-from invalid mailbox: " << efrom;
    }
  }
  else if (spf.kv_map.contains(helo)) {
  }
  else {
    LOG(WARNING)
        << "no explicit \"identity\" key, and no envelope-from or helo key";
  }
}

namespace message {

bool authentication(fs::path         config_path,
                    char const*      server,
                    message::parsed& msg)
{
  LOG(INFO) << "add_authentication_results";
  CHECK(!msg.headers.empty());

  // Run our message through OpenDKIM verify

  OpenDKIM::verify dkv;
  for (auto header : msg.headers) {
    auto const hv = header.as_view();
    // LOG(INFO) << "header «" << esc(hv, esc_line_option::multi) << "»";
    dkv.header(hv);
  }
  dkv.eoh();

  // LOG(INFO) << "body «" << msg.body << "»";
  dkv.body(msg.body);

  dkv.eom();

  OpenDMARC::policy dmp;

  // Build up Authentication-Results header
  fmt::memory_buffer bfr;

  // Grab 1st SPF record
  RFC5322::received_spf_parsed spf_parsed;
  if (auto hdr = std::find(begin(msg.headers), end(msg.headers), Received_SPF);
      hdr != end(msg.headers)) {
    if (spf_parsed.parse(hdr->value)) {
      fmt::format_to(bfr, ";\r\n       spf={}", spf_parsed.result);

      // FIXME get comment in here
      // fmt::format_to(bfr, " ({}) ", );

      if (spf_parsed.kv_map[envelope_from] != spf_parsed.kv_map[helo]) {
        fmt::format_to(bfr, " smtp.helo={}", spf_parsed.kv_map[helo]);
      }
      else {
        fmt::format_to(bfr, " smtp.mailfrom={}",
                       spf_parsed.kv_map[envelope_from]);
      }

      if (spf_parsed.kv_map.contains(client_ip)) {
        std::string ip = make_string(spf_parsed.kv_map[client_ip]);
        dmp.connect(ip.c_str());
      }

      spf_result_to_dmarc(dmp, spf_parsed);
    }
    else {
      LOG(WARNING) << "failed to parse " << hdr->value;
    }
  }

  // Should be only one From:
  if (auto hdr = std::find(begin(msg.headers), end(msg.headers), From);
      hdr != end(msg.headers)) {
    auto const from_str = make_string(hdr->value);

    memory_input<> from_in(from_str, "from");
    if (!parse<RFC5322::mailbox_list_only, RFC5322::addr_specs_action>(
            from_in, msg.from_addrs)) {
      LOG(WARNING) << "failed to parse From:" << from_str;
    }

    for (auto hdr_next = std::next(hdr); hdr_next != end(msg.headers);
         hdr_next      = std::next(hdr_next)) {
      if (*hdr_next == From) {
        LOG(WARNING) << "additional RFC5322.From header found: "
                     << hdr_next->as_string();
      }
    }
  }

  if (msg.from_addrs.empty()) {
    LOG(WARNING) << "No address in RFC5322.From header";
    return false;
  }

  /*
    <https://tools.ietf.org/html/rfc7489#section-6.6>
    6.6.1.  Extract Author Domain

    The case of a syntactically valid multi-valued RFC5322.From field
    presents a particular challenge.  The process in this case is to
    apply the DMARC check using each of those domains found in the
    RFC5322.From field as the Author Domain and apply the most strict
    policy selected among the checks that fail.

  */

  // FIXME
  if (msg.from_addrs.size() > 1) {
    LOG(WARNING) << "More than one address in RFC5322.From header";
  }

  auto from_addr = msg.from_addrs[0];

  boost::trim(from_addr);

  if (!Mailbox::validate(from_addr)) {
    LOG(WARNING) << "Mailbox syntax valid for RFC-5322, not for RFC-5321: \""
                 << from_addr << "\"";
    // Maybe we can pick out a valid domain?
    return false;
  }

  Mailbox from_mbx(from_addr);
  msg.dmarc_from        = from_mbx.as_string(Mailbox::domain_encoding::ascii);
  msg.dmarc_from_domain = from_mbx.domain().ascii();

  LOG(INFO) << "dmarc_from_domain == " << msg.dmarc_from_domain;
  dmp.store_from_domain(msg.dmarc_from_domain.c_str());

  // Check each DKIM sig, inform DMARC processor, put in AR

  dkv.foreach_sig([&dmp, &bfr](char const* domain, bool passed,
                               char const* identity, char const* selector,
                               char const* b) {
    int const result = passed ? DMARC_POLICY_DKIM_OUTCOME_PASS
                              : DMARC_POLICY_DKIM_OUTCOME_FAIL;
    auto const human_result = (passed ? "pass" : "fail");

    LOG(INFO) << "DKIM check for " << domain << " " << human_result;

    dmp.store_dkim(domain, result, human_result);

    auto bs = std::string_view(b, strlen(b)).substr(0, 8);

    fmt::format_to(bfr, ";\r\n       dkim={}", human_result);
    fmt::format_to(bfr, " header.i={}", identity);
    fmt::format_to(bfr, " header.s={}", selector);
    fmt::format_to(bfr, " header.b=\"{}\"", bs);
  });

  // Set DMARC status in AR

  auto const dmarc_passed = dmp.query_dmarc(msg.dmarc_from_domain.c_str());

  auto const dmarc_result = (dmarc_passed ? "pass" : "fail");
  LOG(INFO) << "DMARC " << dmarc_result;

  fmt::format_to(bfr, ";\r\n       dmarc={} header.from={}", dmarc_result,
                 msg.dmarc_from_domain);

  // ARC

  OpenARC::verify arv;
  for (auto header : msg.headers) {
    arv.header(header.as_view());
  }
  arv.eoh();
  arv.body(msg.body);
  arv.eom();

  LOG(INFO) << "ARC status  == " << arv.chain_status_str();
  LOG(INFO) << "ARC custody == " << arv.chain_custody_str();

  auto const arc_status = arv.chain_status_str();

  fmt::format_to(bfr, ";\r\n       arc={}", arc_status);

  // New AR header on the top

  auto const ar_results = [&bfr]() {
    // Ug, OpenARC adds an extra one, arc.c:3213
    auto s = fmt::to_string(bfr);
    if (s.length() && s[0] == ';')
      s.erase(0, 1);
    return s;
  }();

  msg.ar_str =
      fmt::format("{}: {};{}", Authentication_Results, server, ar_results);

  LOG(INFO) << "new AR header " << msg.ar_str;
  CHECK(msg.parse_hdr(msg.ar_str));

  // Run our message through ARC::sign

  OpenARC::sign ars;

  if (iequal(arc_status, "none")) {
    ars.set_cv_none();
  }
  else if (iequal(arc_status, "fail")) {
    ars.set_cv_fail();
  }
  else if (iequal(arc_status, "pass")) {
    ars.set_cv_pass();
  }
  else {
    ars.set_cv_unkn();
  }

  for (auto const& header : msg.headers) {
    ars.header(header.as_view());
  }
  ars.eoh();
  ars.body(msg.body);
  ars.eom();

  auto const key_file = (config_path / selector).replace_extension("private");
  if (!fs::exists(key_file)) {
    LOG(WARNING) << "can't find key file " << key_file;
    return dmarc_passed;
  }
  boost::iostreams::mapped_file_source priv;
  priv.open(key_file);

  if (ars.seal(server, selector, server, priv.data(), priv.size(),
               ar_results.c_str())) {
    msg.arc_hdrs = ars.whole_seal();
    for (auto const& hdr : msg.arc_hdrs) {
      CHECK(msg.parse_hdr(hdr));
    }
  }
  else {
    LOG(INFO) << "failed to generate seal";
  }

  OpenARC::verify arv2;
  for (auto const& header : msg.headers) {
    arv2.header(header.as_view());
  }
  arv2.eoh();
  arv2.body(msg.body);
  arv2.eom();

  LOG(INFO) << "check ARC status  == " << arv2.chain_status_str();
  LOG(INFO) << "check ARC custody == " << arv2.chain_custody_str();

  return dmarc_passed;
}

void print_spf_envelope_froms(char const* file, message::parsed& msg)
{
  CHECK(!msg.headers.empty());
  for (auto const& hdr : msg.headers) {
    if (hdr == Received_SPF) {
      RFC5322::received_spf_parsed spf_parsed;
      if (spf_parsed.parse(hdr.value)) {
        std::cout << spf_parsed.kv_map[envelope_from] << '\n';
        break;
      }
      else {
        LOG(WARNING) << "failed to parse " << file << ":\n" << hdr.as_string();
      }
    }
  }
}

void remove_delivery_headers(message::parsed& msg)
{
  // Remove headers that are added by the "delivery agent"
  // aka (Session::added_headers_)
  msg.headers.erase(
      std::remove(msg.headers.begin(), msg.headers.end(), Return_Path),
      msg.headers.end());

  // just in case, but right now this header should not exist.
  msg.headers.erase(
      std::remove(msg.headers.begin(), msg.headers.end(), Delivered_To),
      msg.headers.end());
}

void dkim_check(fs::path config_path, char const* domain, message::parsed& msg)
{
  LOG(INFO) << "dkim";

  CHECK(!msg.body.empty());

  OpenDKIM::verify dkv;

  // Run our message through OpenDKIM verify

  for (auto header : msg.headers) {
    auto const hv = header.as_view();
    dkv.header(hv);
  }
  dkv.eoh();
  dkv.body(msg.body);
  dkv.eom();

  // Check each DKIM sig, inform DMARC processor, put in AR

  dkv.foreach_sig([](char const* domain, bool passed, char const* identity,
                     char const* selector, char const* b) {
    auto const human_result = (passed ? "pass" : "fail");

    auto bs = std::string_view(b, strlen(b)).substr(0, 8);

    LOG(INFO) << "DKIM check bfor " << domain << " " << human_result;
    LOG(INFO) << " header.i=" << identity;
    LOG(INFO) << " header.s=" << selector;
    LOG(INFO) << " header.b=\"" << bs << "\"";
  });
}

//.............................................................................

bool parsed::parse(std::string_view input)
{
  auto in{memory_input<>(input.data(), input.size(), "message")};
  return tao::pegtl::parse<RFC5322::message, RFC5322::msg_action>(in, *this);
}

bool parsed::parse_hdr(std::string_view input)
{
  auto in{memory_input<>(input.data(), input.size(), "message")};
  if (tao::pegtl::parse<RFC5322::raw_field, RFC5322::msg_action>(in, *this)) {
    std::rotate(headers.rbegin(), headers.rbegin() + 1, headers.rend());
    return true;
  }
  return false;
}

std::string parsed::as_string() const
{
  fmt::memory_buffer bfr;

  for (auto const& h : headers)
    fmt::format_to(bfr, "{}\r\n", h.as_string());

  if (!body.empty())
    fmt::format_to(bfr, "\r\n{}", body);

  return fmt::to_string(bfr);
}

bool parsed::write(std::ostream& os) const
{
  for (auto const& h : headers)
    os << h.as_string() << "\r\n";

  if (!body.empty())
    os << "\r\n" << body;

  return true;
}

std::string header::as_string() const
{
  return fmt::format("{}:{}", name, value);
}

std::string_view parsed::get_header(std::string_view name) const
{
  if (auto hdr = std::find(begin(headers), end(headers), name);
      hdr != end(headers)) {
    return trim(hdr->value);
  }
  return "";
}

void rewrite(fs::path         config_path,
             Domain const&    sender,
             message::parsed& msg,
             std::string      mail_from,
             std::string      reply_to)
{
  LOG(INFO) << "rewrite";

  remove_delivery_headers(msg);

  if (!mail_from.empty()) {
    msg.headers.erase(std::remove(msg.headers.begin(), msg.headers.end(), From),
                      msg.headers.end());

    msg.from_str = mail_from;
    CHECK(msg.parse_hdr(msg.from_str));
  }

  if (!reply_to.empty()) {
    msg.headers.erase(
        std::remove(msg.headers.begin(), msg.headers.end(), Reply_To),
        msg.headers.end());

    msg.reply_to_str = reply_to;
    CHECK(msg.parse_hdr(msg.reply_to_str));
  }

  // modify plain text body

  if (iequal(msg.get_header(MIME_Version), "1.0") &&
      istarts_with(msg.get_header(Content_Type), "text/plain;")) {
    LOG(INFO) << "Adding footer to message body.";
    msg.body_str = msg.body;
    msg.body_str.append("\r\n\r\n\t-- Added Footer --\r\n");
    msg.body = msg.body_str;
  }
  else {
    LOG(INFO) << "Not adding footer to message body.";
    LOG(INFO) << "MIME-Version == " << msg.get_header(MIME_Version);
    LOG(INFO) << "Content-Type == " << msg.get_header(Content_Type);
  }
  // LOG(INFO) << "body == " << msg.body;

  auto const key_file = (config_path / selector).replace_extension("private");
  CHECK(fs::exists(key_file)) << "can't find key file " << key_file;

  // DKIM sign

  boost::iostreams::mapped_file_source priv;
  priv.open(key_file);

  auto const key_str = std::string(priv.data(), priv.size());

  // Run our message through DKIM::sign
  OpenDKIM::sign dks(key_str.c_str(), // textual data
                     selector, sender.ascii().c_str(),
                     OpenDKIM::sign::body_type::text);
  for (auto const& header : msg.headers) {
    dks.header(header.as_view());
  }
  dks.eoh();
  dks.body(msg.body);
  dks.eom();

  fmt::memory_buffer bfr;
  msg.sig_str = fmt::format("DKIM-Signature: {}", dks.getsighdr());
  CHECK(msg.parse_hdr(msg.sig_str));
}

} // namespace message

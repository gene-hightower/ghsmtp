// What you get where:

// RFC5321.HELO/.EHLO domain
// RFC5321.MailFrom   mailbox
// RFC5322.From       mailbox-list

// Reply-To:

// MAIL FROM:<reverse-path>
// RCPT TO:<forward-path>

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
#include <unordered_set>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using std::begin;
using std::end;

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

#include "UTF8.hpp"

//.............................................................................

struct ftext            : ranges<33, 57, 59, 126> {};

struct field_name       : plus<ftext> {};

struct FWS              : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// *([FWS] VCHAR) *WSP
struct field_value      : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {};

struct field            : seq<field_name, colon, field_value, eol> {};

struct raw_field        : seq<field_name, colon, field_value, eof> {};

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

struct obs_local_part   : seq<word, star<seq<dot, word>>> {};

struct local_part       : sor<quoted_string, dot_atom> {};

struct dtext            : ranges<33, 90, 94, 126> {};

struct domain_literal   : seq<opt<CFWS>,
                              one<'['>,
                              star<seq<opt<FWS>, dtext>>,
                              opt<FWS>,
                              one<']'>,
                              opt<CFWS>> {};

struct domain           : sor<dot_atom, domain_literal> {};

struct obs_domain       : sor<list<atom, dot>, domain_literal> {};

// This addr_spec should be exactly the same as RFC5321 Mailbox, but it's not.

struct new_addr_spec    : seq<local_part, one<'@'>, domain> {};

struct obs_addr_spec    : seq<obs_local_part, one<'@'>, obs_domain> {};

struct addr_spec        : sor<obs_addr_spec, new_addr_spec> {};

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

struct obs_domain_list : seq<
                             star<sor<CFWS, one<','>>>, one<'@'>, domain,
                             star<seq<one<','>, opt<CFWS>, opt<seq<one<'@'>, domain>>>>
                            > {};

struct obs_route        : seq<obs_domain_list, colon> {};

struct obs_angle_addr   : seq<opt<CFWS>, one<'<'>, obs_route, addr_spec, one<'>'>, opt<CFWS>> {};

struct angle_addr       : sor<seq<opt<CFWS>, one<'<'>, addr_spec, one<'>'>, opt<CFWS>>,
                              obs_angle_addr
                             > {};

struct display_name     : phrase {};

struct name_addr        : seq<opt<display_name>, angle_addr> {};

struct mailbox          : sor<name_addr, addr_spec> {};

struct obs_mbox_list    : seq<star<seq<opt<CFWS>, one<','>>>,
                              mailbox,
                              star<seq<one<','>, opt<sor<mailbox, CFWS>>>>
                             > {};

struct mailbox_list     : sor<list<mailbox, one<','>>,
                              obs_mbox_list> {};

struct from             : seq<TAO_PEGTL_ISTRING("From"), opt<CFWS>, colon,
                              mailbox_list> {};

struct mailbox_list_only: seq<mailbox_list, eof> {};

//.............................................................................

// <https://www.rfc-editor.org/rfc/rfc2045.html>

//  tspecials :=  "(" / ")" / "<" / ">" / "@" /
//                "," / ";" / ":" / "\" / <">
//                "/" / "[" / "]" / "?" / "="

//  token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
//              or tspecials>

// CTL   0..31 127
// SPACE 32

// tspecials
// 34     "
// 40..41 ()
// 44     ,
// 47     /
// 58..64 ;:<=>?@
// 91..93 [\]
// 127    DEL

struct tchar45          : ranges<        // NUL..' '
                                 33, 33, // !
                              // 34, 34, // "
                                 35, 39, // #$%&'
                              // 40, 41, // ()
                                 42, 43, // *+
                              // 44, 44, // ,
                                 45, 46, // -.
                              // 47, 47, // /
                                 48, 57, // 0123456789
                              // 58, 64, // ;:<=>?@
                                 65, 90, // A..Z
                              // 91, 93, // [\]
                                 94, 126 // ^_` a..z {|}~
                              // 127,127 // DEL
                                > {};

struct token45          : plus<tchar45> {};

//.............................................................................

// <https://tools.ietf.org/html/rfc8601#section-2.2>

struct value            : sor<token45, quoted_string> {};

struct authserv_id      :  value {};

struct authres_version  : seq<plus<DIGIT>, opt<CFWS>> {};

struct no_result        : seq<opt<CFWS>, one<';'>, opt<CFWS>, TAO_PEGTL_ISTRING("none")> {};

struct let_dig          : sor<ALPHA, DIGIT> {};

struct ldh_tail         : star<sor<seq<plus<one<'-'>>, let_dig>, let_dig>> {};

struct ldh_str          : seq<let_dig, ldh_tail> {};

struct keyword          : ldh_str {};

struct method_version   : seq<plus<DIGIT>, opt<CFWS>> {};

//     method = Keyword [ [CFWS] "/" [CFWS] method-version ]

struct method           : seq<keyword, opt<opt<CFWS>, one<'/'>, opt<CFWS>, method_version>> {};

//     methodspec = [CFWS] method [CFWS] "=" [CFWS] result
//                ; indicates which authentication method was evaluated
//                ; and what its output was

struct methodspec       : seq<opt<CFWS>, method, opt<CFWS>, one<'='>, opt<CFWS>, result> {};

//     reasonspec = "reason" [CFWS] "=" [CFWS] value
//                ; a free-form comment on the reason the given result
//                ; was returned

struct reasonspec       : seq<TAO_PEGTL_ISTRING("reason"), opt<CFWS>, one<'='>, opt<CFWS>, value> {};

//     pvalue = [CFWS] ( value / [ [ local-part ] "@" ] domain-name )
//              [CFWS]

struct pvalue           : seq<opt<CFWS>, sor<seq<opt<seq<opt<local_part>, one<'@'>>>, domain>,
                                             value>,
                              opt<CFWS>> {};

struct ptype            : keyword {};

struct special_smtp_verb: sor<TAO_PEGTL_ISTRING("mailfrom"),
                              TAO_PEGTL_ISTRING("rcptto")> {};

struct property         : sor<special_smtp_verb, keyword> {};

//     propspec = ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue
//              ; an indication of which properties of the message
//              ; were evaluated by the authentication scheme being
//              ; applied to yield the reported result

struct propspec         : seq<ptype, opt<CFWS>, dot, opt<CFWS>, property, opt<CFWS>, one<'='>, pvalue> {};

struct resinfo          : seq<opt<CFWS>, one<';'>, methodspec, opt<seq<CFWS, reasonspec>>,
                              opt<seq<CFWS, plus<propspec>>>
                             > {};

struct ar_results       : sor<no_result, plus<resinfo>> {};

struct authres_payload  : seq<opt<CFWS>, authserv_id,
                              opt<seq<CFWS, authres_version>>,
                              ar_results,
                              opt<CFWS>> {};

struct authres_header_field: seq<TAO_PEGTL_ISTRING("Authentication-Results"), opt<CFWS>, colon,
                                 authres_payload> {};

struct authres_header_field_only: seq<authres_header_field, eof> {};

//.............................................................................

// clang-format on

template <typename Rule>
struct ar_action : nothing<Rule> {
};

template <>
struct ar_action<ar_results> {
  template <typename Input>
  static void
  apply(Input const& in, std::string& authservid, std::string& ar_results)
  {
    ar_results = in.string();
  }
};

template <>
struct ar_action<authserv_id> {
  template <typename Input>
  static void
  apply(Input const& in, std::string& authservid, std::string& ar_results)
  {
    authservid = in.string();
  }
};

//.............................................................................

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

  std::string_view whole_thing;

  std::string_view result;
  std::string_view comment;

  std::string_view key;
  std::string_view value;

  std::vector<std::pair<std::string_view, std::string_view>> kv_list;
  std::map<std::string_view, std::string_view, ci_less>      kv_map;

  std::string as_string() const { return fmt::format("{}", whole_thing); }
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
struct spf_action<comment> {
  template <typename Input>
  static void apply(const Input& in, received_spf_parsed& spf)
  {
    spf.comment = make_view(in);
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
    for (auto const& kvp : spf.kv_list) {
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
  whole_thing = input;
  auto in{memory_input<>(input.data(), input.size(), "spf_header")};
  return tao::pegtl::parse<spf_header_only, spf_action>(in, *this);
}

//.............................................................................

template <typename Rule>
struct mailbox_list_action : nothing<Rule> {};

template <>
struct mailbox_list_action<local_part> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    LOG(INFO) << "local_part: " << in.string();
  }
};

template <>
struct mailbox_list_action<domain> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    LOG(INFO) << "domain: " << in.string();
  }
};

template <>
struct mailbox_list_action<obs_local_part> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    LOG(INFO) << "obs_local_part: " << in.string();
  }
};

template <>
struct mailbox_list_action<obs_domain> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    LOG(INFO) << "obs_domain: " << in.string();
  }
};

template <>
struct mailbox_list_action<display_name> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    from_parsed.maybe_name = in.string();
  }
};

template <>
struct mailbox_list_action<angle_addr> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    std::swap(from_parsed.name, from_parsed.maybe_name);
  }
};

template <>
struct mailbox_list_action<addr_spec> {
  template <typename Input>
  static void apply(Input const&                       in,
                    ::message::mailbox_name_addr_list& from_parsed)
  {
    from_parsed.name_addr_list.push_back({from_parsed.name, in.string()});
    from_parsed.name.clear();
    from_parsed.maybe_name.clear();
  }
};

} // namespace RFC5322

// Map SPF result string to DMARC policy code.

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

static bool is_postmaster(std::string_view from)
{
  return from == "<>" || iequal(from, "<Postmaster>") ||
         istarts_with(from, "<Postmaster@");
}

static bool sender_comment(std::string_view comment, std::string_view sender)
{
  auto const prefix = fmt::format("({}:", sender);
  return istarts_with(comment, prefix);
}

static void spf_result_to_dmarc(OpenDMARC::policy&            dmp,
                                RFC5322::received_spf_parsed& spf)
{
  LOG(INFO) << "spf_result_to_dmarc";

  if (spf.kv_map.contains(problem)) {
    LOG(WARNING) << "SPF problem: " << spf.kv_map[problem];
  }

  auto const spf_pol = result_to_pol(spf.result);

  if (spf_pol == DMARC_POLICY_SPF_OUTCOME_NONE) {
    LOG(WARNING) << "Ignoring for DMARC purposes: " << spf.as_string();
    return;
  }

  std::string spf_dom;

  int spf_origin;

  if (spf.kv_map.contains(identity)) {
    if (iequal(spf.kv_map[identity], mailfrom)) {
      if (spf.kv_map.contains(envelope_from)) {
        if (Mailbox::validate(spf.kv_map[envelope_from])) {
          Mailbox mbx(spf.kv_map[envelope_from]);
          spf_dom    = mbx.domain().ascii();
          spf_origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;

          auto const human_result =
              fmt::format("{}, explicit origin mail from, mailbox {}",
                          spf.result, mbx.as_string());
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
              "{}, explicit origin hello, domain {}", spf.result, dom.ascii());
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

    if (is_postmaster(efrom)) {
      if (spf.kv_map.contains(helo)) {
        if (Domain::validate(spf.kv_map[helo])) {
          Domain dom(spf.kv_map[helo]);
          spf_dom    = dom.ascii();
          spf_origin = DMARC_POLICY_SPF_ORIGIN_HELO;

          auto const human_result = fmt::format(
              "{}, RFC5321.MailFrom is <>, implicit origin hello, domain {}",
              spf.result, dom.ascii());
          LOG(INFO) << "SPF result " << human_result;
          dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin,
                        human_result.c_str());
          return;
        }
        else {
          LOG(WARNING) << "RFC5321.MailFrom is postmaster or <> but helo is "
                          "invalid domain:"
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
          "{}, implicit RFC5321.MailFrom <{}>", spf.result, mbx.as_string());
      LOG(INFO) << "SPF result " << human_result;
      dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin, human_result.c_str());
      return;
    }
    else {
      LOG(WARNING) << "envelope-from invalid mailbox: " << efrom;
    }
  }
  else if (spf.kv_map.contains(helo)) {
    if (Domain::validate(spf.kv_map[helo])) {
      Domain dom(spf.kv_map[helo]);
      spf_dom    = dom.ascii();
      spf_origin = DMARC_POLICY_SPF_ORIGIN_HELO;

      auto const human_result =
          fmt::format("{}, hello domain {}", spf.result, dom.ascii());
      LOG(INFO) << "SPF result " << human_result;
      dmp.store_spf(spf_dom.c_str(), spf_pol, spf_origin, human_result.c_str());
      return;
    }
    else {
      LOG(WARNING) << "helo is invalid domain:" << spf.kv_map[helo];
    }
  }
  else {
    LOG(WARNING)
        << "no explicit \"identity\" key, and no envelope-from or helo key";
  }
}

namespace message {

bool mailbox_list_parse(std::string_view        input,
                        mailbox_name_addr_list& name_addr_list)
{
  name_addr_list = mailbox_name_addr_list{};
  auto in{memory_input<>(input.data(), input.size(), "mailbox_list_only")};
  return tao::pegtl::parse<RFC5322::mailbox_list_only,
                           RFC5322::mailbox_list_action>(in, name_addr_list);
}

bool authentication_results_parse(std::string_view input,
                                  std::string&     authservid,
                                  std::string&     ar_results)
{
  auto in{memory_input<>(input.data(), input.size(),
                         "authentication_results_header")};
  return tao::pegtl::parse<RFC5322::authres_header_field_only,
                           RFC5322::ar_action>(in, authservid, ar_results);
}

bool authentication(message::parsed& msg,
                    char const*      sender,
                    char const*      selector,
                    fs::path         key_file)
{
  LOG(INFO) << "add_authentication_results";
  CHECK(!msg.headers.empty());

  // Remove any redundant Authentication-Results headers
  msg.headers.erase(
      std::remove_if(msg.headers.begin(), msg.headers.end(),
                     [sender](auto const& hdr) {
                       if (hdr == Authentication_Results) {
                         std::string authservid;
                         std::string ar_results;
                         if (message::authentication_results_parse(
                                 hdr.as_view(), authservid, ar_results)) {
                           return Domain::match(authservid, sender);
                         }
                         LOG(WARNING) << "failed to parse " << hdr.as_string();
                       }
                       return false;
                     }),
      msg.headers.end());

  // Run our message through OpenDKIM verify

  OpenDKIM::verify dkv;
  for (auto const& header : msg.headers) {
    auto const hv = header.as_view();
    dkv.header(hv);
  }
  dkv.eoh();

  // LOG(INFO) << "body «" << msg.body << "»";
  dkv.body(msg.body);

  dkv.eom();

  OpenDMARC::policy dmp;

  // Build up Authentication-Results header
  fmt::memory_buffer bfr;

  std::unordered_set<Domain> validated_doms;

  // Grab SPF records
  for (auto hdr : msg.headers) {
    if (hdr == Received_SPF) {
      RFC5322::received_spf_parsed spf_parsed;
      if (!spf_parsed.parse(hdr.value)) {
        LOG(WARNING) << "failed to parse SPF record: " << hdr.value;
        continue;
      }

      LOG(INFO) << "SPF record parsed";
      if (!sender_comment(spf_parsed.comment, sender)) {
        LOG(INFO) << "comment == \"" << spf_parsed.comment << "\" not by "
                  << sender;
        continue;
      }

      if (!Mailbox::validate(spf_parsed.kv_map[envelope_from])) {
        LOG(WARNING) << "invalid mailbox: " << spf_parsed.kv_map[envelope_from];
        continue;
      }

      if (!Domain::validate(spf_parsed.kv_map[helo])) {
        LOG(WARNING) << "invalid helo domain: " << spf_parsed.kv_map[helo];
        continue;
      }

      Mailbox env_from(spf_parsed.kv_map[envelope_from]);
      Domain  helo_dom(spf_parsed.kv_map[helo]);

      if (iequal(env_from.local_part(), "Postmaster") &&
          env_from.domain() == helo_dom) {
        if (validated_doms.count(helo_dom) == 0) {
          fmt::format_to(std::back_inserter(bfr), ";\r\n\tspf={}",
                         spf_parsed.result);
          fmt::format_to(std::back_inserter(bfr), " {}", spf_parsed.comment);
          fmt::format_to(std::back_inserter(bfr), " smtp.helo={}",
                         helo_dom.ascii());
          validated_doms.emplace(helo_dom);

          if (spf_parsed.kv_map.contains(client_ip)) {
            std::string ip = make_string(spf_parsed.kv_map[client_ip]);
            dmp.connect(ip.c_str());
          }
          spf_result_to_dmarc(dmp, spf_parsed);
        }
      }
      else {
        if (validated_doms.count(env_from.domain()) == 0) {
          fmt::format_to(std::back_inserter(bfr), ";\r\n\tspf={}",
                         spf_parsed.result);
          fmt::format_to(std::back_inserter(bfr), " {}", spf_parsed.comment);
          fmt::format_to(std::back_inserter(bfr), " smtp.mailfrom={}",
                         env_from.as_string(Mailbox::domain_encoding::ascii));
          validated_doms.emplace(env_from.domain());

          if (spf_parsed.kv_map.contains(client_ip)) {
            std::string ip = make_string(spf_parsed.kv_map[client_ip]);
            dmp.connect(ip.c_str());
          }
          spf_result_to_dmarc(dmp, spf_parsed);
        }
      }
    }
  }

  LOG(INFO) << "fetching From: header";
  // Should be only one From:
  if (auto hdr = std::find(begin(msg.headers), end(msg.headers), From);
      hdr != end(msg.headers)) {
    auto const from_str = make_string(hdr->value);

    if (!mailbox_list_parse(from_str, msg.from_parsed)) {
      LOG(WARNING) << "failed to parse «From:" << from_str << "»";
    }

    for (auto hdr_next = std::next(hdr); hdr_next != end(msg.headers);
         hdr_next      = std::next(hdr_next)) {
      if (*hdr_next == From) {
        LOG(WARNING) << "additional RFC5322.From header «"
                     << hdr_next->as_string() << "»";
      }
    }
  }

  if (msg.from_parsed.name_addr_list.empty()) {
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
  if (msg.from_parsed.name_addr_list.size() > 1) {
    LOG(WARNING) << "More than one address in RFC5322.From header";
  }

  auto from_addr = msg.from_parsed.name_addr_list[0].addr;

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
                               char const* identity, char const* sel,
                               char const* b) {
    int const  result       = passed ? DMARC_POLICY_DKIM_OUTCOME_PASS
                                     : DMARC_POLICY_DKIM_OUTCOME_FAIL;
    auto const human_result = (passed ? "pass" : "fail");

    LOG(INFO) << "DKIM check for " << domain << " " << human_result;

    dmp.store_dkim(domain, sel, result, human_result);

    auto bs = std::string_view(b, strlen(b)).substr(0, 8);

    fmt::format_to(std::back_inserter(bfr), ";\r\n\tdkim={}", human_result);
    fmt::format_to(std::back_inserter(bfr), " header.i={}", identity);
    fmt::format_to(std::back_inserter(bfr), " header.s={}", sel);
    fmt::format_to(std::back_inserter(bfr), " header.b=\"{}\"", bs);
  });

  // Set DMARC status in AR

  auto const dmarc_passed = dmp.query_dmarc(msg.dmarc_from_domain.c_str());

  auto const dmarc_result = (dmarc_passed ? "pass" : "fail");
  LOG(INFO) << "DMARC " << dmarc_result;

  fmt::format_to(std::back_inserter(bfr), ";\r\n\tdmarc={} header.from={}",
                 dmarc_result, msg.dmarc_from_domain);

  // ARC

  OpenARC::verify arv;
  for (auto const& header : msg.headers) {
    arv.header(header.as_view());
  }
  arv.eoh();
  arv.body(msg.body);
  arv.eom();

  LOG(INFO) << "ARC status  == " << arv.chain_status_str();
  LOG(INFO) << "ARC custody == " << arv.chain_custody_str();

  auto const arc_status = arv.chain_status_str();

  fmt::format_to(std::back_inserter(bfr), ";\r\n\tarc={}", arc_status);

  // New AR header on the top

  auto const ar_results = [&bfr]() {
    // Ug, OpenARC adds an extra one, arc.c:3213
    auto s = fmt::to_string(bfr);
    if (s.length() && s[0] == ';')
      s.erase(0, 1);
    return s;
  }();

  msg.ar_str =
      fmt::format("{}: {};{}", Authentication_Results, sender, ar_results);

  LOG(INFO) << "new AR header «" << esc(msg.ar_str, esc_line_option::multi)
            << "»";

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

  boost::iostreams::mapped_file_source priv;
  priv.open(key_file);

  if (ars.seal(sender, selector, sender, priv.data(), priv.size(),
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

void dkim_check(message::parsed& msg, char const* domain)
{
  LOG(INFO) << "dkim";

  CHECK(!msg.body.empty());

  OpenDKIM::verify dkv;

  // Run our message through OpenDKIM verify

  for (auto const& header : msg.headers) {
    auto const hv = header.as_view();
    dkv.header(hv);
  }
  dkv.eoh();
  dkv.body(msg.body);
  dkv.eom();

  // Check each DKIM sig, inform DMARC processor, put in AR

  dkv.foreach_sig([](char const* domain, bool passed, char const* identity,
                     char const* sel, char const* b) {
    auto const human_result = (passed ? "pass" : "fail");

    auto bs = std::string_view(b, strlen(b)).substr(0, 8);

    LOG(INFO) << "DKIM check bfor " << domain << " " << human_result;
    LOG(INFO) << " header.i=" << identity;
    LOG(INFO) << " header.s=" << sel;
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
    fmt::format_to(std::back_inserter(bfr), "{}\r\n", h.as_string());

  if (!body.empty())
    fmt::format_to(std::back_inserter(bfr), "\r\n{}", body);

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

void dkim_sign(message::parsed& msg,
               char const*      sender,
               char const*      selector,
               fs::path         key_file)
{
  CHECK(msg.sig_str.empty());

  boost::iostreams::mapped_file_source priv;
  priv.open(key_file);

  auto const key_str = std::string(priv.data(), priv.size());

  // Run our message through DKIM::sign
  OpenDKIM::sign dks(key_str.c_str(), // textual data
                     selector, sender, OpenDKIM::sign::body_type::text);
  for (auto const& header : msg.headers) {
    dks.header(header.as_view());
  }
  dks.eoh();
  dks.body(msg.body);
  dks.eom();

  auto const sig = dks.getsighdr();

  msg.sig_str = fmt::format("DKIM-Signature: {}", sig);
  CHECK(msg.parse_hdr(msg.sig_str));
}

void rewrite_from_to(message::parsed& msg,
                     std::string      mail_from,
                     std::string      reply_to,
                     char const*      sender,
                     char const*      selector,
                     fs::path         key_file)
{
  LOG(INFO) << "rewrite_from_to";

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

  /*
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
  */

  dkim_sign(msg, sender, selector, key_file);
}

} // namespace message

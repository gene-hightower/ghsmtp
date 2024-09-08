// Toy RFC-5322 message parser and DMARC validator.

#include <gflags/gflags.h>
namespace gflags {
// in case we didn't have one
}

DEFINE_bool(selftest, false, "run a self test");

#include <map>
#include <string>
#include <vector>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/device/mapped_file.hpp>

#include <iostream>

#include "Mailbox.hpp"
#include "OpenDKIM.hpp"
#include "OpenDMARC.hpp"
#include "SPF.hpp"
#include "esc.hpp"
#include "fs.hpp"
#include "iequal.hpp"
#include "osutil.hpp"

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

// #include <tao/pegtl/contrib/tracer.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
  return N;
}

namespace RFC5322 {

constexpr char const* defined_fields[]{

    // Trace Fields
    "Return-Path",
    "Received",
    "Received-SPF", // RFC 7208 added trace field

    // Sig
    "DKIM-Signature", // RFC 7489

    // Originator Fields
    "Date",
    "From",
    "Sender",
    "Reply-To",

    // Destination Address Fields
    "To",
    "Cc",
    "Bcc",

    // Identification Fields
    "Message-ID",
    "In-Reply-To",
    "References",

    // Informational Fields
    "Subject",
    "Comments",
    "Keywords",

    // Resent Fields
    "Resent-Date",
    "Resent-From",
    "Resent-Sender",
    "Resent-To",
    "Resent-Cc",
    "Resent-Bcc",
    "Resent-Message-ID",

    // MIME Fields
    "MIME-Version",

    "Content-Type",
    "Content-Transfer-Encoding",
    "Content-ID",
    "Content-Description",
};

bool is_defined_field(std::string_view name)
{
  return std::find_if(std::begin(defined_fields), std::end(defined_fields),
                      [=](std::string_view v) { return iequal(name, v); })
         != std::end(defined_fields);
}

char const* defined_field(std::string_view name)
{
  auto df = std::find_if(std::begin(defined_fields), std::end(defined_fields),
                         [=](std::string_view v) { return iequal(name, v); });
  if (df != std::end(defined_fields))
    return *df;
  return "";
}

struct ci_less {
  bool operator()(std::string const& lhs, std::string const& rhs) const
  {
    return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
  }
};

struct Ctx {
  OpenDKIM::verify dkv;

  OpenDMARC::policy dmp;

  std::string mb_loc;
  std::string mb_dom;

  std::vector<::Mailbox> mb_list; // temporary accumulator

  std::vector<::Mailbox> from_list;

  ::Mailbox sender;

  std::string key;
  std::string value;

  std::vector<std::pair<std::string, std::string>> kv_list;

  std::map<std::string, std::string, ci_less> spf_info;
  std::string                                 spf_result;

  std::unordered_multimap<char const*, std::string> defined_hdrs;
  std::multimap<std::string, std::string, ci_less>  opt_hdrs;

  std::string unstructured;
  std::string id;

  std::string message_id;

  std::string opt_name;
  std::string opt_value;

  std::string type;
  std::string subtype;

  bool mime_version{false};
  bool discrete_type{false};
  bool composite_type{false};

  std::vector<std::pair<std::string, std::string>> ct_parameters;

  std::vector<std::string> msg_errors;
};

// clang-format off

struct UTF8_tail : range<'\x80', '\xBF'> {};

struct UTF8_1 : range<0x00, 0x7F> {};

struct UTF8_2 : seq<range<'\xC2', '\xDF'>, UTF8_tail> {};

struct UTF8_3 : sor<seq<one<'\xE0'>, range<'\xA0', '\xBF'>, UTF8_tail>,
                    seq<range<'\xE1', '\xEC'>, rep<2, UTF8_tail>>,
                    seq<one<'\xED'>, range<'\x80', '\x9F'>, UTF8_tail>,
                    seq<range<'\xEE', '\xEF'>, rep<2, UTF8_tail>>> {};

struct UTF8_4
  : sor<seq<one<'\xF0'>, range<'\x90', '\xBF'>, rep<2, UTF8_tail>>,
        seq<range<'\xF1', '\xF3'>, rep<3, UTF8_tail>>,
        seq<one<'\xF4'>, range<'\x80', '\x8F'>, rep<2, UTF8_tail>>> {};

// UTF8_char = UTF8_1 | UTF8_2 | UTF8_3 | UTF8_4;

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

struct VUCHAR : sor<VCHAR, UTF8_non_ascii> {};

using dot   = one<'.'>;
using colon = one<':'>;

struct text : sor<ranges<1, 9, 11, 12, 14, 127>, UTF8_non_ascii> {};

// UTF-8 except NUL (0), LF (10) and CR (13).
// struct body : seq<star<seq<rep_max<998, text>, eol>>, rep_max<998, text>> {};

// BINARYMIME allows any byte
struct body : until<eof> {};

struct FWS : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

struct qtext : sor<one<33>, ranges<35, 91, 93, 126>, UTF8_non_ascii> {};

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
                   UTF8_non_ascii> {};

// ctext is ASCII not '(' or ')' or '\\'
struct ctext : sor<ranges<33, 39, 42, 91, 93, 126>, UTF8_non_ascii> {};

// <https://tools.ietf.org/html/rfc2047>

//   especials = "(" / ")" / "<" / ">" / "@" / "," / ";" / ":" / "
//               <"> / "/" / "[" / "]" / "?" / "." / "="

//   token = 1*<Any CHAR except SPACE, CTLs, and especials>

struct tchar47 : ranges<        // NUL..' '
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

struct token47 : plus<tchar47> {};

struct charset : token47 {};
struct encoding : token47 {};

//   encoded-text = 1*<Any printable ASCII character other than "?"
//                     or SPACE>

struct echar : ranges<        // NUL..' '
                      33, 62, // !..>
                   // 63, 63, // ?
                      64, 126 // @A..Z[\]^_` a..z {|}~
                   // 127,127 // DEL
                     > {};

struct encoded_text : plus<echar> {};

//   encoded-word = "=?" charset "?" encoding "?" encoded-text "?="

// leading opt<FWS> is not in RFC 2047

struct encoded_word_book : seq<string<'=', '?'>,
                          charset, string<'?'>,
                          encoding, string<'?'>,
                          encoded_text,
                          string<'=', '?'>
                          > {};

struct encoded_word : seq<opt<FWS>, encoded_word_book> {};

struct comment;

struct ccontent : sor<ctext, quoted_pair, comment, encoded_word> {};

// from <https://tools.ietf.org/html/rfc2047>
// comment = "(" *(ctext / quoted-pair / comment / encoded-word) ")"

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

//   obs-phrase      =   word *(word / "." / CFWS)

struct phrase : plus<sor<encoded_word, word>> {};

struct dec_octet : sor<seq<string<'2','5'>, range<'0','5'>>,
                       seq<one<'2'>, range<'0','4'>, DIGIT>,
                       seq<one<'1'>, rep<2, DIGIT>>,
                       seq<range<'1', '9'>, DIGIT>,
                       DIGIT
                      > {};
struct ipv4_address
  : seq<dec_octet, dot, dec_octet, dot, dec_octet, dot, dec_octet> {};

struct h16 : rep_min_max<1, 4, HEXDIG> {};

struct ls32 : sor<seq<h16, colon, h16>, ipv4_address> {};

struct dcolon : two<':'> {};

struct ipv6_address : sor<seq<                                          rep<6, h16, colon>, ls32>,
                          seq<                                  dcolon, rep<5, h16, colon>, ls32>,
                          seq<opt<h16                        >, dcolon, rep<4, h16, colon>, ls32>, 
                          seq<opt<h16,     opt<   colon, h16>>, dcolon, rep<3, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<2, colon, h16>>, dcolon, rep<2, h16, colon>, ls32>,
                          seq<opt<h16, rep_opt<3, colon, h16>>, dcolon,        h16, colon,  ls32>,
                          seq<opt<h16, rep_opt<4, colon, h16>>, dcolon,                     ls32>,
                          seq<opt<h16, rep_opt<5, colon, h16>>, dcolon,                      h16>,
                          seq<opt<h16, rep_opt<6, colon, h16>>, dcolon                          >> {};

struct ip : sor<ipv4_address, ipv6_address> {};

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

struct angle_addr : seq<opt<CFWS>, one<'<'>, addr_spec, one<'>'>, opt<CFWS>> {};

struct path
  : sor<angle_addr, seq<opt<CFWS>, one<'<'>, opt<CFWS>, one<'>'>, opt<CFWS>>> {};

struct display_name : phrase {};

struct name_addr : seq<opt<display_name>, angle_addr> {};

struct name_addr_only : seq<name_addr, eof> {};

struct mailbox : sor<name_addr, addr_spec> {};

struct group_list;

struct group
  : seq<display_name, one<':'>, opt<group_list>, one<';'>, opt<CFWS>> {};

struct address : sor<mailbox, group> {};

#define OBSOLETE_SYNTAX

#ifdef OBSOLETE_SYNTAX
// *([CFWS] ",") mailbox *("," [mailbox / CFWS])
struct obs_mbox_list : seq<star<seq<opt<CFWS>, one<','>>>,
                           mailbox,
                           star<one<','>, opt<sor<mailbox, CFWS>>>> {};

struct mailbox_list : sor<list<mailbox, one<','>>, obs_mbox_list> {};
#else
struct mailbox_list : list<mailbox, one<','>> {};
#endif

#ifdef OBSOLETE_SYNTAX
// *([CFWS] ",") address *("," [address / CFWS])
struct obs_addr_list : seq<star<seq<opt<CFWS>, one<','>>>,
                           address,
                           star<one<','>, opt<sor<address, CFWS>>>> {};

struct address_list : sor<list<address, one<','>>, obs_addr_list> {};
#else
struct address_list : list<address, one<','>> {};
#endif

#ifdef OBSOLETE_SYNTAX
// 1*([CFWS] ",") [CFWS]
struct obs_group_list : seq<plus<seq<opt<CFWS>, one<','>>>, opt<CFWS>> {};

struct group_list : sor<mailbox_list, CFWS, obs_group_list> {};
#else
struct group_list : sor<mailbox_list, CFWS> {};
#endif

// 3.3. Date and Time Specification (mostly from RFC 2822)

struct day : seq<opt<FWS>, rep_min_max<1, 2, DIGIT>> {};

struct month_name : sor<TAO_PEGTL_ISTRING("Jan"),
                        TAO_PEGTL_ISTRING("Feb"),
                        TAO_PEGTL_ISTRING("Mar"),
                        TAO_PEGTL_ISTRING("Apr"),
                        TAO_PEGTL_ISTRING("May"),
                        TAO_PEGTL_ISTRING("Jun"),
                        TAO_PEGTL_ISTRING("Jul"),
                        TAO_PEGTL_ISTRING("Aug"),
                        TAO_PEGTL_ISTRING("Sep"),
                        TAO_PEGTL_ISTRING("Oct"),
                        TAO_PEGTL_ISTRING("Nov"),
                        TAO_PEGTL_ISTRING("Dec")> {};

struct month : seq<FWS, month_name, FWS> {};

struct year : rep<4, DIGIT> {};

struct date : seq<day, month, year> {};

struct day_name : sor<TAO_PEGTL_ISTRING("Mon"),
                      TAO_PEGTL_ISTRING("Tue"),
                      TAO_PEGTL_ISTRING("Wed"),
                      TAO_PEGTL_ISTRING("Thu"),
                      TAO_PEGTL_ISTRING("Fri"),
                      TAO_PEGTL_ISTRING("Sat"),
                      TAO_PEGTL_ISTRING("Sun")> {};

// struct obs_day_of_week : seq<opt<CFWS>, day_name, opt<CFWS>> {
// };

// struct obs_day : seq<opt<CFWS>, rep_min_max<1, 2, DIGIT>, opt<CFWS>> {
// };

// struct obs_year : seq<opt<CFWS>, rep<2, DIGIT>, opt<CFWS>> {
// };

// struct obs_hour : seq<opt<CFWS>, rep<2, DIGIT>, opt<CFWS>> {
// };

// struct obs_minute : seq<opt<CFWS>, rep<2, DIGIT>, opt<CFWS>> {
// };

// struct obs_second : seq<opt<CFWS>, rep<2, DIGIT>, opt<CFWS>> {
// };

// struct obs_day_of_week : seq<opt<CFWS>, day_name, opt<CFWS>> {
// }

struct day_of_week : seq<opt<FWS>, day_name> {};

struct hour : rep<2, DIGIT> {};

struct minute : rep<2, DIGIT> {};

struct second : rep<2, DIGIT> {};

struct millisecond : rep<3, DIGIT> {};

// RFC-5322 extension is optional milliseconds
struct time_of_day
  : seq<hour,
        one<':'>,
        minute,
        opt<seq<one<':'>, second, opt<seq<one<'.'>, millisecond>>>>> {};

// struct obs_zone : sor<range<65, 73>,
//                       range<75, 90>,
//                       range<97, 105>,
//                       range<107, 122>,
//                       TAO_PEGTL_ISTRING("UT"),
//                       TAO_PEGTL_ISTRING("GMT"),
//                       TAO_PEGTL_ISTRING("EST"),
//                       TAO_PEGTL_ISTRING("EDT"),
//                       TAO_PEGTL_ISTRING("CST"),
//                       TAO_PEGTL_ISTRING("CDT"),
//                       TAO_PEGTL_ISTRING("MST"),
//                       TAO_PEGTL_ISTRING("MDT"),
//                       TAO_PEGTL_ISTRING("PST"),
//                       TAO_PEGTL_ISTRING("PDT")> {
// };

struct zone : seq<sor<one<'+'>, one<'-'>>, rep<4, DIGIT>> {};

struct time : seq<time_of_day, FWS, zone> {};

struct date_time
  : seq<opt<seq<day_of_week, one<','>>>, date, FWS, time, opt<CFWS>> {};

// The Origination Date Field
struct orig_date : seq<TAO_PEGTL_ISTRING("Date:"), date_time, eol> {};

// Originator Fields
struct from : seq<TAO_PEGTL_ISTRING("From:"), opt<FWS>, mailbox_list, opt<FWS>, eol> {};

struct sender : seq<TAO_PEGTL_ISTRING("Sender:"), mailbox, eol> {};

struct reply_to : seq<TAO_PEGTL_ISTRING("Reply-To:"), address_list, eol> {};

struct address_list_or_pm : sor<TAO_PEGTL_ISTRING("Postmaster"), address_list> {};

// Destination Address Fields
struct to : seq<TAO_PEGTL_ISTRING("To:"), address_list_or_pm, eol> {};

struct cc : seq<TAO_PEGTL_ISTRING("Cc:"), address_list, eol> {};

struct bcc : seq<TAO_PEGTL_ISTRING("Bcc:"), opt<sor<address_list, CFWS>>, eol> {};

// Identification Fields

struct no_fold_literal : seq<one<'['>, star<dtext>, one<']'>> {};

struct id_left : dot_atom_text {};

struct id_right : sor<dot_atom_text, no_fold_literal> {};

struct msg_id
  : seq<opt<CFWS>, one<'<'>, id_left, one<'@'>, id_right, one<'>'>, opt<CFWS>> {};

struct message_id : seq<TAO_PEGTL_ISTRING("Message-ID:"), msg_id, eol> {};

struct in_reply_to : seq<TAO_PEGTL_ISTRING("In-Reply-To:"), plus<msg_id>, eol> {};

struct references : seq<TAO_PEGTL_ISTRING("References:"), star<msg_id>, eol> {};

// Informational Fields

struct subject : seq<TAO_PEGTL_ISTRING("Subject:"), unstructured, eol> {};

struct comments : seq<TAO_PEGTL_ISTRING("Comments:"), unstructured, eol> {};

struct keywords
  : seq<TAO_PEGTL_ISTRING("Keywords:"), list<phrase, one<','>>, eol> {};

// Resent Fields

struct resent_date : seq<TAO_PEGTL_ISTRING("Resent-Date:"), date_time, eol> {};

struct resent_from : seq<TAO_PEGTL_ISTRING("Resent-From:"), mailbox_list, eol> {};

struct resent_sender : seq<TAO_PEGTL_ISTRING("Resent-Sender:"), mailbox, eol> {};

struct resent_to : seq<TAO_PEGTL_ISTRING("Resent-To:"), address_list, eol> {};

struct resent_cc : seq<TAO_PEGTL_ISTRING("Resent-Cc:"), address_list, eol> {};

struct resent_bcc
  : seq<TAO_PEGTL_ISTRING("Resent-Bcc:"), opt<sor<address_list, CFWS>>, eol> {};

struct resent_msg_id
  : seq<TAO_PEGTL_ISTRING("Resent-Message-ID:"), msg_id, eol> {};

// Trace Fields

struct return_path : seq<TAO_PEGTL_ISTRING("Return-Path:"), opt<FWS>, path, eol> {};

// Facebook, among others

struct return_path_non_standard : seq<TAO_PEGTL_ISTRING("Return-Path:"),
                                      opt<CFWS>,
                                      addr_spec,
                                      star<WSP>,
                                      eol> {};

struct received_token : sor<angle_addr, addr_spec, domain, word> {};

struct received : seq<TAO_PEGTL_ISTRING("Received:"),
                      opt<sor<plus<received_token>, CFWS>>,
                      one<';'>,
                      date_time,
                      opt<seq<WSP, comment>>,
                      eol> {};

struct result : sor<TAO_PEGTL_ISTRING("Pass"),
                    TAO_PEGTL_ISTRING("Fail"),
                    TAO_PEGTL_ISTRING("SoftFail"),
                    TAO_PEGTL_ISTRING("Neutral"),
                    TAO_PEGTL_ISTRING("None"),
                    TAO_PEGTL_ISTRING("TempError"),
                    TAO_PEGTL_ISTRING("PermError")> {};

struct spf_key : sor<TAO_PEGTL_ISTRING("client-ip"),
                     TAO_PEGTL_ISTRING("envelope-from"),
                     TAO_PEGTL_ISTRING("helo"),
                     TAO_PEGTL_ISTRING("problem"),
                     TAO_PEGTL_ISTRING("receiver"),
                     TAO_PEGTL_ISTRING("identity"),
                     TAO_PEGTL_ISTRING("mechanism")> {};

// This value syntax (allowing addr_spec and angle_addr) is not in
// accordance with RFC 7208 (or 4408) but is what is effectivly used
// by libspf2 1.2.10 and before.

struct spf_value : sor<ip, addr_spec, dot_atom, quoted_string, angle_addr> {};

struct spf_key_value_pair : seq<spf_key, opt<CFWS>, one<'='>, spf_value> {};

struct spf_key_value_list
  : seq<spf_key_value_pair,
        star<seq<one<';'>, opt<CFWS>, spf_key_value_pair>>,
        opt<one<';'>>> {};

struct received_spf : seq<TAO_PEGTL_ISTRING("Received-SPF:"),
                          opt<CFWS>,
                          result,
                          opt<seq<FWS, comment>>,
                          opt<seq<FWS, spf_key_value_list>>,
                          eol> {};

struct dkim_signature
  : seq<TAO_PEGTL_ISTRING("DKIM-Signature:"), unstructured, eol> {};

struct mime_version : seq<TAO_PEGTL_ISTRING("MIME-Version:"),
                          opt<CFWS>,
                          one<'1'>,
                          opt<CFWS>,
                          one<'.'>,
                          opt<CFWS>,
                          one<'0'>,
                          opt<CFWS>,
                          eol> {};

// CTL :=  <any ASCII control           ; (  0- 37,  0.- 31.)
//          character and DEL>          ; (    177,     127.)

// SPACE := 32

// especials :=  "(" / ")" / "<" / ">" / "@" /
//               "," / ";" / ":" / "\" / <">
//               "/" / "[" / "]" / "?" / "="

// ! 33

// 33-33

// "  34

// 35-39

// (  40
// )  41

// 42-43

// ,  44

// 45-46

// /  47

// 48-57

// :  58
// ;  59
// <  60
// =  61
// >  62
// ?  63
// @  64

// 65-90

// [  91
// \  92
// ]  93

// 94-126

// token := 1*<any (US-ASCII) CHAR except CTLs, SPACE,
//            or tspecials>

struct tchar : ranges<33, 33, 35, 39, 42, 43, 45, 46, 48, 57, 65, 90, 94, 126> {};

struct token : plus<tchar> {};

struct ietf_token : token {};

struct x_token : seq<TAO_PEGTL_ISTRING("X-"), token> {};

struct extension_token : sor<x_token, ietf_token> {};

struct discrete_type : sor<TAO_PEGTL_ISTRING("text"),
                           TAO_PEGTL_ISTRING("image"),
                           TAO_PEGTL_ISTRING("audio"),
                           TAO_PEGTL_ISTRING("video"),
                           TAO_PEGTL_ISTRING("application"),
                           extension_token> {};

struct composite_type : sor<TAO_PEGTL_ISTRING("message"),
                            TAO_PEGTL_ISTRING("multipart"),
                            extension_token> {};

struct type : sor<discrete_type, composite_type> {};

struct subtype : token {};

// value     := token / quoted-string

// attribute := token

// parameter := attribute "=" value

struct value : sor<token, quoted_string> {};

struct attribute : token {};

struct parameter : seq<attribute, one<'='>, value> {};

struct content : seq<TAO_PEGTL_ISTRING("Content-Type:"),
                     opt<CFWS>,
                     seq<type, one<'/'>, subtype>,
                     star<seq<one<';'>, opt<CFWS>, parameter>>,
                     opt<one<';'>>, // not strictly RFC 2045, but common
                     eol> {};

// mechanism := "7bit" / "8bit" / "binary" /
//              "quoted-printable" / "base64" /
//              ietf-token / x-token

struct mechanism : sor<TAO_PEGTL_ISTRING("7bit"),
                       TAO_PEGTL_ISTRING("8bit"),
                       TAO_PEGTL_ISTRING("binary"),
                       TAO_PEGTL_ISTRING("quoted-printable"),
                       TAO_PEGTL_ISTRING("base64"),
                       ietf_token,
                       x_token> {};

struct content_transfer_encoding
  : seq<TAO_PEGTL_ISTRING("Content-Transfer-Encoding:"),
        opt<CFWS>,
        mechanism,
        eol> {};

struct id : seq<TAO_PEGTL_ISTRING("Content-ID:"), msg_id, eol> {};

struct description
  : seq<TAO_PEGTL_ISTRING("Content-Description:"), star<text>, eol> {};

// Optional Fields

struct ftext : ranges<33, 57, 59, 126> {};

struct field_name : plus<ftext> {};

struct field_value : unstructured {};

struct optional_field : seq<field_name, one<':'>, field_value, eol> {};

// message header

struct fields : star<sor<
                         return_path,
                         return_path_non_standard,
                         received,
                         received_spf,

                         dkim_signature,

                         orig_date,
                         from,
                         sender,
                         reply_to,

                         to,
                         cc,
                         bcc,

                         message_id,
                         in_reply_to,
                         references,

                         subject,
                         comments,
                         keywords,

                         resent_date,
                         resent_from,
                         resent_sender,
                         resent_to,
                         resent_cc,
                         resent_bcc,
                         resent_msg_id,

                         mime_version,
                         content,
                         content_transfer_encoding,
                         id,
                         description,

                         optional_field
                       >> {};

struct message : seq<fields, opt<seq<eol, body>>, eof> {};

// clang-format on

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<fields> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    // LOG(INFO) << "fields";
  }
};

template <>
struct action<unstructured> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.unstructured = in.string();
  }
};

template <>
struct action<field_name> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.opt_name = in.string();
  }
};

template <>
struct action<field_value> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.opt_value = in.string();
  }
};

template <typename Input>
static void header(Input const& in, Ctx& ctx)
{
  ctx.dkv.header(std::string_view(begin(in), end(in) - begin(in)));
}

template <>
struct action<optional_field> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    // LOG(INFO) << "optional_field";
    if (is_defined_field(ctx.opt_name)) {
      // So, this is a syntax error in a defined field.
      if (ctx.opt_name == "Received") {
        // Go easy on Received lines, they tend to be wild and woolly.
        // LOG(INFO) << in.string();
      }
      else {
        auto const err
            = fmt::format("syntax error in: \"{}\"", esc(in.string()));
        ctx.msg_errors.push_back(err);
        LOG(ERROR) << err;
      }
      ctx.defined_hdrs.emplace(defined_field(ctx.opt_name), ctx.opt_value);
    }
    else {
      ctx.opt_hdrs.emplace(ctx.opt_name, ctx.opt_value);
    }
    header(in, ctx);
    ctx.unstructured.clear();
    ctx.mb_list.clear();
  }
};

template <>
struct action<local_part> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.mb_loc = in.string();
    boost::trim(ctx.mb_loc);
  }
};

template <>
struct action<domain> {
  template <typename Input>
  static void apply(Input const& in, Ctx& ctx)
  {
    ctx.mb_dom = in.string();
    // LOG(INFO) << "domain == '" << ctx.mb_dom << "'";
  }
};

template <>
struct action<mailbox> {
  static void apply0(Ctx& ctx)
  {
    // LOG(INFO) << "mailbox emplace_back(" << ctx.mb_loc << '@' << ctx.mb_dom
    // << ')';
    ctx.mb_list.emplace_back(ctx.mb_loc, Domain{ctx.mb_dom});
  }
};

template <>
struct action<orig_date> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    // LOG(INFO) << "Date:";
    header(in, ctx);
  }
};

// Originator Fields

template <>
struct action<from> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    if (!ctx.from_list.empty()) {
      fmt::memory_buffer msg;
      fmt::format_to(std::back_inserter(msg),
                     "multiple 'From:' address headers, previous:\n");
      for (auto const& add : ctx.from_list) {
        fmt::format_to(std::back_inserter(msg), " {}\n", add.as_string());
      }
      fmt::format_to(std::back_inserter(msg), "new: {}", in.string());
      ctx.msg_errors.push_back(fmt::to_string(msg));
    }

    header(in, ctx);
    ctx.from_list = std::move(ctx.mb_list);
    ctx.mb_list.clear();
  }
};

template <>
struct action<sender> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    if (!ctx.sender.empty()) {
      auto const err
          = fmt::format("multiple 'Sender:' headers, previous: {}, this: {}",
                        static_cast<std::string>(ctx.sender), in.string());
      ctx.msg_errors.push_back(err);
    }
    header(in, ctx);
    CHECK_EQ(ctx.mb_list.size(), 1);
    ctx.sender = std::move(ctx.mb_list[0]);
    ctx.mb_list.clear();
  }
};

template <>
struct action<reply_to> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

// Destination Address Fields

template <>
struct action<to> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<cc> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<bcc> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

// Identification Fields

template <>
struct action<msg_id> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.id = in.string();
    boost::trim(ctx.id);
  }
};

template <>
struct action<message_id> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    if (!ctx.message_id.empty()) {
      LOG(ERROR) << "multiple message IDs: " << ctx.message_id << " and "
                 << ctx.id;
    }
    ctx.message_id = ctx.id;
  }
};

template <>
struct action<in_reply_to> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

template <>
struct action<references> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

// Informational Fields

template <>
struct action<subject> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.unstructured.clear();
  }
};

template <>
struct action<comments> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.unstructured.clear();
  }
};

template <>
struct action<keywords> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

// Resent Fields

template <>
struct action<resent_date> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

template <>
struct action<resent_from> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<resent_sender> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<resent_to> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<resent_cc> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<resent_bcc> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<resent_msg_id> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

// Trace Fields

template <>
struct action<return_path> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<return_path_non_standard> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    // LOG(INFO) << "Return-Path: is retarded: " << esc(in.string());
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<received> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mb_list.clear();
  }
};

template <>
struct action<result> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.spf_result = std::move(in.string());
    boost::to_lower(ctx.spf_result);
  }
};

template <>
struct action<spf_key> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.key = std::move(in.string());
  }
};

template <>
struct action<spf_value> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.value = std::move(in.string());
    boost::trim(ctx.value);
  }
};

template <>
struct action<spf_key_value_pair> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.kv_list.emplace_back(ctx.key, ctx.value);
    ctx.key.clear();
    ctx.value.clear();
  }
};

template <>
struct action<spf_key_value_list> {
  static void apply0(Ctx& ctx)
  {
    for (auto kvp : ctx.kv_list) {
      ctx.spf_info[kvp.first] = kvp.second;
    }
  }
};

template <>
struct action<received_spf> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    // LOG(INFO) << "Received-SPF:";

    // Do a fresh check now:

    auto node = osutil::get_hostname();

    SPF::Server  spf_srv(node.c_str());
    SPF::Request spf_req(spf_srv);

    spf_req.set_ip_str(ctx.spf_info["client-ip"].c_str());

    spf_req.set_helo_dom(ctx.spf_info["helo"].c_str());
    if (ctx.spf_info.find("envelope-from") != end(ctx.spf_info)) {
      spf_req.set_env_from(ctx.spf_info["envelope-from"].c_str());
    }

    SPF::Response spf_res(spf_req);
    auto          res = spf_res.result();
    CHECK_NE(res, SPF::Result::INVALID);

    if (ctx.spf_result != res.c_str()) {
      LOG(WARNING) << "SPF results changed: "
                   << "new result is \"" << res << "\", old result is \""
                   << ctx.spf_result << "\"";
    }

    // Get result from header:

    int pol_spf = DMARC_POLICY_SPF_OUTCOME_PASS;

    // Pass is the default:
    // if (ctx.spf_result == "pass") {
    //   pol_spf = DMARC_POLICY_SPF_OUTCOME_PASS;
    // }

    // if ((ctx.spf_result == "neutral") || (ctx.spf_result == "softfail")) {
    //   // could also be a FAIL maybe...
    //   pol_spf = DMARC_POLICY_SPF_OUTCOME_PASS;
    // }

    if (ctx.spf_result == "none") {
      pol_spf = DMARC_POLICY_SPF_OUTCOME_NONE;
    }

    if (ctx.spf_result == "temperror") {
      pol_spf = DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
    }

    if ((ctx.spf_result == "fail") || (ctx.spf_result == "permerror")) {
      pol_spf = DMARC_POLICY_SPF_OUTCOME_FAIL;
    }

    if (ctx.spf_info.find("client-ip") != end(ctx.spf_info)) {
      ctx.dmp.connect(ctx.spf_info["client-ip"].c_str());
      // LOG(INFO) << "SPF: ip==" << ctx.spf_info["client-ip"] << ", "
      //           << ctx.spf_result;
    }

    // Google sometimes doesn't put in anything but client-ip
    if (ctx.spf_info.find("envelope-from") != end(ctx.spf_info)) {
      auto dom    = ctx.spf_info["envelope-from"];
      auto origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;

      if (dom == "<>") {
        dom    = ctx.spf_info["helo"];
        origin = DMARC_POLICY_SPF_ORIGIN_HELO;
        LOG(INFO) << "SPF: origin HELO " << dom;
      }
      else {
        memory_input<> addr_in(dom, "dom");
        if (!parse<RFC5322::addr_spec, RFC5322::action>(addr_in, ctx)) {
          LOG(FATAL) << "Failed to parse domain: " << dom;
        }
        dom    = ctx.mb_dom;
        origin = DMARC_POLICY_SPF_ORIGIN_MAILFROM;
        LOG(INFO) << "SPF: origin MAIL FROM " << dom;

        ctx.mb_loc.clear();
        ctx.mb_dom.clear();
      }
      ctx.dmp.store_spf(dom.c_str(), pol_spf, origin, "are you human?");
    }

    ctx.mb_list.clear();
  }
};

template <>
struct action<dkim_signature> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    CHECK(ctx.dkv.sig_syntax(ctx.unstructured)) << ctx.unstructured;
    ctx.unstructured.clear();
  }
};

template <>
struct action<received_token> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
  }
};

template <>
struct action<mime_version> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    ctx.mime_version = true;
  }
};

template <>
struct action<content> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    // ctx.unstructured.clear();
  }
};

template <>
struct action<discrete_type> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.discrete_type = true;
    ctx.type          = in.string();
  }
};

template <>
struct action<composite_type> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.composite_type = true;
    ctx.type           = in.string();
  }
};

template <>
struct action<subtype> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.subtype = in.string();
  }
};

template <>
struct action<content_transfer_encoding> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
    // ctx.unstructured.clear();
  }
};

template <>
struct action<id> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

template <>
struct action<description> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    header(in, ctx);
  }
};

template <>
struct action<attribute> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.key = in.string();
  }
};

template <>
struct action<parameter> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.ct_parameters.emplace_back(ctx.key, ctx.value);
    ctx.key.clear();
    ctx.value.clear();
  }
};

template <>
struct action<value> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    ctx.value = in.string();
  }
};

template <>
struct action<body> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    // LOG(INFO) << "Message body:";
    auto const body = std::string_view(begin(in), end(in) - begin(in));

    ctx.dkv.eoh();
    ctx.dkv.body(body);

    if (ctx.mime_version) {
      // std::stringstream type;
      // type << "Content-Type: " << ctx.type << "/" << ctx.subtype;
      // for (auto const& p : ctx.ct_parameters) {
      //   if ((type.str().length() + (3 + p.first.length() +
      //   p.second.length()))
      //       > 78)
      //     type << ";\r\n\t";
      //   else
      //     type << "; ";
      //   type << p.first << "=" << p.second;
      // }
      // LOG(INFO) << type.str();

      // memory_input<> body_in(body, "body");
      // if (!parse_nested<RFC5322::, RFC5322::action>(in, body_in, ctx)) {
      //   LOG(ERROR) << "bad mime body";
      // }
    }
  }
};

template <>
struct action<message> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    // LOG(INFO) << "message";
    ctx.dkv.eom();

    // ctx.dkv.check();

    Domain from_domain;

    if (ctx.from_list.empty()) {
      // RFC-5322 says message must have a 'From:' header.
      LOG(ERROR) << "no (correct) RFC5322.From header";

      auto range = ctx.defined_hdrs.equal_range(defined_field("From"));
      for (auto it = range.first; it != range.second; ++it) {
        LOG(ERROR) << "using bogus '" << it->second << "'";
        // ctx.from_list.push_back(Mailbox(it->second));
      }

      if (ctx.from_list.empty())
        return;
    }

    if (ctx.from_list.size() > 1) {

      LOG(INFO) << ctx.from_list.size() << "multiple RFC5322.From addresses";
      for (auto& f : ctx.from_list) {
        LOG(INFO) << f;
      }

      if (ctx.sender.empty()) {
        // Must have 'Sender:' says RFC-5322 section 3.6.2.
        LOG(ERROR)
            << "no RFC5322.Sender header with multiple RFC5322.From mailboxes";
        return;
      }

      // find sender in from list
      // auto s = find(begin(ctx.from_list), end(ctx.from_list), ctx.sender);
      // if (s == end(ctx.from_list)) {
      //   // can't be found, not an error
      //   LOG(ERROR) << "No 'From:' match to 'Sender:'";

      //   // must check all From:s
      //   LOG(FATAL) << "write code to check all From: addresses";
      // }
      // else {
      //   from_domain = ctx.sender;
      //   LOG(INFO) << "using 'Sender:' domain " << ctx.sender.domain();
      // }
    }
    else {

      from_domain = ctx.from_list[0].domain();

      // if (!ctx.sender.empty()) {
      //   if (from_domain != ctx.sender.domain()) {
      //     LOG(INFO) << "using 'Sender:' domain " << ctx.sender.domain()
      //               << " in place of 'From:' domain " << from_domain;
      //     from_domain = ctx.sender.domain();
      //   }
      // }
    }

    ctx.dmp.store_from_domain(from_domain.ascii().c_str());

    ctx.dkv.foreach_sig([&ctx](char const* domain, bool passed,
                               char const* identity, char const* selector,
                               char const* b) {
      LOG(INFO) << "DKIM check for " << domain
                << (passed ? " passed" : " failed");

      int result = passed ? DMARC_POLICY_DKIM_OUTCOME_PASS
                          : DMARC_POLICY_DKIM_OUTCOME_FAIL;

      ctx.dmp.store_dkim(domain, selector, result, "I am human");
    });

    ctx.dmp.query_dmarc(from_domain.ascii().c_str());

    // LOG(INFO) << "Message-ID: " << ctx.message_id;
    // LOG(INFO) << "Final DMARC advice for " << from_domain << ": "
    //           << Advice_to_string(ctx.dmp.get_advice());

    if (ctx.msg_errors.size()) {
      for (auto e : ctx.msg_errors) {
        LOG(ERROR) << e;
      }
    }
  }
};

template <>
struct action<obs_mbox_list> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    LOG(INFO) << "obsolete mailbox list: " << esc(in.string());
  }
};

template <>
struct action<obs_addr_list> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    LOG(INFO) << "obsolete address list: " << esc(in.string());
  }
};

template <>
struct action<obs_group_list> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    LOG(INFO) << "obsolete group list: " << esc(in.string());
  }
};

template <>
struct action<angle_addr> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    //    LOG(INFO) << "angle_addr: " << in.string();
  }
};
template <>
struct action<display_name> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    //    LOG(INFO) << "display_name: " << in.string();
  }
};
template <>
struct action<name_addr> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    //    LOG(INFO) << "name_addr: " << in.string();
  }
};
template <>
struct action<name_addr_only> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    //    LOG(INFO) << "name_addr_only: " << in.string();
  }
};
} // namespace RFC5322

void display(RFC5322::Ctx const& ctx)
{
  // for (auto const& [name, value] : ctx.defined_hdrs) {
  //   std::cout << name << ": " << value << '\n';
  // }
  // for (auto const& [name, value] : ctx.opt_hdrs) {
  //   std::cout << name << ": " << value << '\n';
  // }
}

void selftest()
{
  const char* name_addr_list_bad[]{
      "Gene Hightower . <gene@digilicious.com>",
      "via.Relay. <noreply@relay.firefox.com>",
      "[via Relay] <noreply@relay.firefox.com>",
  };

  for (auto i : name_addr_list_bad) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (parse<RFC5322::name_addr_only,
              RFC5322::action /*, tao::pegtl::tracer*/>(in, ctx)) {
      LOG(FATAL) << "Should not parse as name_addr_only \"" << i << "\"";
    }
  }

  const char* name_addr_list_good[]{
      "Gene Hightower <gene@digilicious.com>",
      "via Relay <noreply@relay.firefox.com>",
      "\"Gene Hightower <gene@digilicious.com> [via Relay]\""
      "<noreply@relay.firefox.com>",
      "\"Customer Care <care@bigcompany.com> via foo.com\" <noreply@foo.com>",
  };

  for (auto i : name_addr_list_good) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (!parse<RFC5322::name_addr_only,
               RFC5322::action /*, tao::pegtl::tracer*/>(in, ctx)) {
      LOG(FATAL) << "Error parsing as name_addr_only \"" << i << "\"";
    }
  }

  CHECK(RFC5322::is_defined_field("Subject"));
  CHECK(!RFC5322::is_defined_field("X-Subject"));

  const char* ip_list[]{
      "2607:f8b0:4001:c0b::22a",
      "127.0.0.1",
  };

  for (auto i : ip_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (!parse<RFC5322::ip, RFC5322::action /*, tao::pegtl::tracer*/>(in,
                                                                      ctx)) {
      LOG(ERROR) << "Error parsing as ip \"" << i << "\"";
    }
  }

  const char* rec_list[]{
      // github
      "Received: from github-smtp2a-ext-cp1-prd.iad.github.net "
      "(github-smtp2a-ext-cp1-prd.iad.github.net [192.30.253.16])\r\n"
      " by ismtpd0004p1iad1.sendgrid.net (SG) with ESMTP id "
      "OCAkwxSQQTiPcF-T3rLS3w\r\n"
      "	for <gene-github@digilicious.com>; Tue, 23 May 2017 "
      "23:01:49.124 +0000 (UTC)\r\n",

      // sendgrid date is shit
      // "Received: by filter0810p1mdw1.sendgrid.net with SMTP id "
      // "filter0810p1mdw1-13879-5924BDA5-34\r\n"
      // "        2017-05-23 22:54:29.679063164 +0000 UTC\r\n",

  };

  for (auto i : rec_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (!parse<RFC5322::received, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Received: \"" << i << "\"";
    }
  }

  const char* date_list[]{
      "Date: Tue, 30 May 2017 10:52:11 +0000 (UTC)\r\n",
      "Date: Mon, 29 May 2017 16:47:58 -0700\r\n",

      // this date is shit
      // "Date: Mon, 29 May 2017 19:47:08 EDT\r\n",
  };

  for (auto i : date_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (!parse<RFC5322::orig_date, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Date: \"" << i << "\"";
    }
  }

  const char* const spf_list[]{
      // works
      "Received-SPF: pass (digilicious.com: domain of gmail.com designates "
      "74.125.82.46 as permitted sender) client-ip=74.125.82.46; "
      "envelope-from=l23456789O@gmail.com; helo=mail-wm0-f46.google.com;\r\n",

      // also works
      "Received-SPF: neutral (google.com: 2607:f8b0:4001:c0b::22a is neither "
      "permitted nor denied by best guess record for domain of "
      "1234567@riscv.org) client-ip=2607:f8b0:4001:c0b::22a;\r\n",
  };

  for (auto i : spf_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx   ctx;
    if (!parse<RFC5322::received_spf, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Received-SPF: \"" << i << "\"";
    }
  }
}

int main(int argc, char* argv[])
{
  { // Need to work with either namespace.
    using namespace gflags;
    using namespace google;
    ParseCommandLineFlags(&argc, &argv, true);
  }

  if (FLAGS_selftest) {
    selftest();
    return 0;
  }

  for (auto i{1}; i < argc; ++i) {
    auto fn{argv[i]};
    auto name{fs::path(fn)};
    auto f{boost::iostreams::mapped_file_source(name)};
    auto in{memory_input<>(f.data(), f.size(), fn)};
    LOG(INFO) << "#### file: " << fn;
    try {
      RFC5322::Ctx ctx;
      // ctx.defined_hdrs.reserve(countof(RFC5322::defined_fields));
      if (!parse<RFC5322::message, RFC5322::action>(in, ctx)) {
        LOG(ERROR) << "parse returned false";
      }
      display(ctx);
    }
    catch (parse_error const& e) {
      std::cerr << e.what();
      return 1;
    }
  }
  return 0;
}

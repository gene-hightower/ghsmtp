#include "rewrite.hpp"

#include "OpenARC.hpp"
#include "OpenDKIM.hpp"
#include "OpenDMARC.hpp"
#include "esc.hpp"
#include "imemstream.hpp"

#include <cstring>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <boost/iostreams/device/mapped_file.hpp>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

using namespace std::string_literals;

namespace {
template <typename Input>
std::string_view make_view(Input const& in)
{
  return std::string_view(in.begin(), std::distance(in.begin(), in.end()));
}
} // namespace

namespace RFC5322 {

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

struct UTF8_non_ascii : sor<UTF8_2, UTF8_3, UTF8_4> {};

struct VUCHAR         : sor<VCHAR, UTF8_non_ascii> {};

struct ftext          : ranges<33, 57, 59, 126> {};

struct field_name     : plus<ftext> {};

struct FWS            : seq<opt<seq<star<WSP>, eol>>, plus<WSP>> {};

// *([FWS] VCHAR) *WSP
struct field_value    : seq<star<seq<opt<FWS>, VUCHAR>>, star<WSP>> {};

struct field          : seq<field_name, one<':'>, field_value, eol> {};

struct fields         : star<field> {};

struct body           : until<eof> {};

struct message        : seq<fields, opt<seq<eol, body>>, eof> {};

// clang-format on

namespace data {

struct field {
  field(std::string_view n, std::string_view v)
    : name(n)
    , value(v)
  {
  }

  std::string_view name;
  std::string_view value;
};

struct message {

  bool parse(std::string_view msg);
  void index();

  std::string as_string() const;

  std::vector<field> headers;

  std::unordered_map<std::string_view, std::string_view> header_index;

  std::string_view body;

  std::string_view field_name;
  std::string_view field_value;
};
} // namespace data

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<field_name> {
  template <typename Input>
  static void apply(Input const& in, data::message& msg)
  {
    msg.field_name = make_view(in);
  }
};

template <>
struct action<field_value> {
  template <typename Input>
  static void apply(Input const& in, data::message& msg)
  {
    msg.field_value = make_view(in);
  }
};

template <>
struct action<field> {
  template <typename Input>
  static void apply(Input const& in, data::message& msg)
  {
    msg.headers.emplace_back(data::field(msg.field_name, msg.field_value));
  }
};

template <>
struct action<body> {
  template <typename Input>
  static void apply(Input const& in, data::message& msg)
  {
    msg.body = make_view(in);
  }
};

bool data::message::parse(std::string_view input)
{
  auto in{memory_input<>(input.data(), input.size(), "message")};
  return tao::pegtl::parse<RFC5322::message, RFC5322::action>(in, *this);
}

void data::message::index()
{
  header_index.clear();
  header_index.reserve(headers.size());
  for (auto const h : headers)
    header_index[h.name] = h.value;
}

std::string data::message::as_string() const
{
  fmt::memory_buffer bfr;

  for (auto const h : headers)
    fmt::format_to(bfr, "{}:{}\r\n", h.name, h.value);

  if (!body.empty())
    fmt::format_to(bfr, "\r\n{}", body);

  return fmt::to_string(bfr);
}

} // namespace RFC5322

static void do_arc(char const* domain, RFC5322::data::message& msg)
{
  OpenDKIM::Verify dkv;

  OpenARC::lib lib;
  char const*  error = nullptr;
  auto         arc   = lib.message(ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
                         ARC_SIGN_RSASHA256, ARC_MODE_VERIFY, &error);

  for (auto field : msg.headers) {
    auto const header = fmt::format("{}:{}", field.name, field.value);
    // LOG(INFO) << "header «" << header << "»";
    arc.header(header);
    dkv.header(header);
  }
  dkv.eoh();
  arc.eoh();

  // LOG(INFO) << "body «" << msg.body << "»";
  arc.body(msg.body);
  dkv.body(msg.body);

  arc.eom();
  dkv.eom();

  OpenDMARC::Policy dmp;

  dkv.foreach_sig([&dmp](char const* domain, bool passed) {
    LOG(INFO) << "DKIM check for " << domain
              << (passed ? " passed" : " failed");

    int result = passed ? DMARC_POLICY_DKIM_OUTCOME_PASS
                        : DMARC_POLICY_DKIM_OUTCOME_FAIL;

    dmp.store_dkim(domain, result, nullptr);
  });

  LOG(INFO) << "status  == " << arc.chain_status_str();
  LOG(INFO) << "custody == " << arc.chain_custody_str();

  if ("fail"s == arc.chain_status_str()) {
    LOG(INFO) << "existing failed ARC set, doing nothing more";
    return;
  }

  ARC_HDRFIELD* seal = nullptr;

  /*
  boost::iostreams::mapped_file_source priv;
  priv.open("ghsmtp.private");

  CHECK_EQ(
      arc.seal(&seal, dom, "arc", dom, priv.data(), priv.size(), nullptr),
      ARC_STAT_OK)
      << arc.geterror();
  */

  if (seal) {
    auto const nam = OpenARC::hdr::name(seal);
    auto const val = OpenARC::hdr::value(seal);
    LOG(INFO) << nam << ": " << val;
  }
  else {
    LOG(INFO) << "no seal";
  }
}

std::optional<std::string> rewrite(char const* domain, std::string_view input)
{
  RFC5322::data::message msg;

  if (!msg.parse(input)) {
    LOG(WARNING) << "failed to parse message";
    return {};
  }
  msg.index();

  do_arc(domain, msg);

  return msg.as_string();
}

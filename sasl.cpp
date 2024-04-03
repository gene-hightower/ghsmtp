#include "Base64.hpp"
#include "SockBuffer.hpp"

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>

#include <iostream>
#include <string>
#include <unordered_map>

#include <fmt/format.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/types.h>

#include <glog/logging.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

#include "test-credentials.ipp"

using namespace std::string_literals;

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

namespace dovecot {
// clang-format off

using HYPHEN = one<'-'>;
using UNDERSCORE = one<'_'>;

struct id : plus<DIGIT> {};
struct pid : plus<DIGIT> {};
struct cookie : rep<32, HEXDIG> {};

struct base64_char : sor<ALPHA, DIGIT, one<'+'>, one<'/'>> {};
struct base64_data : seq<plus<base64_char>, rep_min_max<0, 2, one<'='>>> {};

struct param_char : sor<ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct param_name : rep_min_max<1, 20, param_char> {};

struct param_vchar : not_one<'\t'> {};
struct param_val : rep_min_max<1, 200, param_vchar> {};

struct parameter : sor<param_name, seq<param_name, one<'='>, param_val>> {};

struct UPPER_ALPHA : range<'A', 'Z'> {};

struct mech_char : sor<UPPER_ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct sasl_mech : rep_min_max<1, 20, mech_char> {};

struct vers : seq<TAO_PEGTL_STRING("VERSION"), HTAB, one<'1'>, HTAB, DIGIT, LF> {};
struct mech : seq<TAO_PEGTL_STRING("MECH"), HTAB, sasl_mech, star<seq<HTAB, parameter>>, LF> {};
struct spid : seq<TAO_PEGTL_STRING("SPID"), HTAB, pid, LF> {};
struct cuid : seq<TAO_PEGTL_STRING("CUID"), HTAB, pid, LF> {};
struct cook : seq<TAO_PEGTL_STRING("COOKIE"), HTAB, cookie, LF> {};
struct done : seq<TAO_PEGTL_STRING("DONE"), LF> {};

struct resp : seq<vers, star<mech>, spid, cuid, cook, done, discard> {};

struct auth_ok : seq<TAO_PEGTL_STRING("OK"), HTAB, id, star<seq<HTAB, parameter>>> {};
struct auth_cont : seq<TAO_PEGTL_STRING("CONT"), HTAB, id, HTAB, base64_data> {};
struct auth_fail : seq<TAO_PEGTL_STRING("FAIL"), HTAB, id, star<seq<HTAB, parameter>>> {};

struct auth_resp : seq<sor<auth_ok, auth_cont, auth_fail>, discard> {};

// clang-format on

struct Context {
  using parameters_t = std::vector<std::string>;
  using mechs_t      = std::unordered_map<std::string, parameters_t>;

  uint32_t    id;
  std::string cookie;
  std::string sasl_mech;

  parameters_t parameters;
  mechs_t      mechs;

  enum class auth_response { none, ok, cont, fail };

  // clang-format off
  static constexpr auto none = auth_response::none;
  static constexpr auto ok   = auth_response::ok;
  static constexpr auto cont = auth_response::cont;
  static constexpr auto fail = auth_response::fail;

  static constexpr char const* c_str(auth_response rsp)
  {
    switch (rsp) {
    case none: return "none";
    case ok:   return "ok";
    case cont: return "cont";
    case fail: return "fail";
    }
    return "** unknown **";
  }
  // clang-format on

  auth_response auth_resp{none};
};

std::ostream& operator<<(std::ostream& os, Context::auth_response rsp)
{
  return os << Context::c_str(rsp);
}

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<id> {
  template <typename Input>
  static void apply(Input const& in, Context& ctx)
  {
    ctx.id = strtoul(in.string().c_str(), nullptr, 10);
  }
};

template <>
struct action<cookie> {
  template <typename Input>
  static void apply(Input const& in, Context& ctx)
  {
    ctx.cookie = in.string();
  }
};

template <>
struct action<parameter> {
  template <typename Input>
  static void apply(Input const& in, Context& ctx)
  {
    ctx.parameters.push_back(in.string());
  }
};

template <>
struct action<sasl_mech> {
  template <typename Input>
  static void apply(Input const& in, Context& ctx)
  {
    ctx.sasl_mech = in.string();
  }
};

template <>
struct action<mech> {
  template <typename Input>
  static void apply(Input const& in, Context& ctx)
  {
    ctx.mechs.emplace(std::move(ctx.sasl_mech), std::move(ctx.parameters));
  }
};

template <>
struct action<auth_ok> {
  static void apply0(Context& ctx)
  {
    ctx.auth_resp = Context::auth_response::ok;
  }
};

template <>
struct action<auth_cont> {
  static void apply0(Context& ctx)
  {
    ctx.auth_resp = Context::auth_response::cont;
  }
};

template <>
struct action<auth_fail> {
  static void apply0(Context& ctx)
  {
    ctx.auth_resp = Context::auth_response::fail;
  }
};
} // namespace dovecot

// clang-format off
constexpr char const* defined_params[]{
    "anonymous",
    "plaintext",
    "dictionary",
    "active",
    "forward-secrecy",
    "mutual-auth",
    "private",
};
// clang-format on

int main()
{
  auto const fd{socket(AF_UNIX, SOCK_STREAM, 0)};
  PCHECK(fd >= 0) << "socket failed";

  sockaddr_un addr = {.sun_family = AF_UNIX,
                      .sun_path = "/var/spool/postfix/private/auth" };

  PCHECK(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
      << "connect to " << addr.sun_path << " failed";

  auto ios{boost::iostreams::stream<SockBuffer>{fd, fd}};

  ios << "VERSION\t1\t1\n"
      << "CPID\t" << getpid() << "\n"
      << std::flush;

  auto ctx = dovecot::Context{};
  auto in  = istream_input<eol::lf, 1>{ios, 8 * 1024, "sasl"};
  if (!parse<dovecot::resp, dovecot::action>(in, ctx)) {
    LOG(WARNING) << "handshake response parse failed";
  }

  for (auto const& m : ctx.mechs) {
    LOG(INFO) << m.first;
  }

  auto const tok{fmt::format(std::string_view("\0{}\0{}", 6), test::username, test::password)};
  auto const init{Base64::enc(tok)};

  if (ctx.mechs.find("PLAIN") != end(ctx.mechs)) {
    auto id{uint32_t{0x12345678}};

    ios << "AUTH\t" << id << "\tPLAIN"
        << "\tservice=SMTP"
        << "\tresp=" << init << '\n'
        << std::flush;

    if (!parse<dovecot::auth_resp, dovecot::action>(in, ctx)) {
      LOG(WARNING) << "auth response parse failed";
    }

    CHECK_EQ(ctx.id, id);
    LOG(INFO) << "AUTH: " << ctx.auth_resp;
  }
}

#include "Base64.hpp"
//#include "SockBuffer.hpp"

#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>

#include <experimental/string_view>
#include <iostream>
#include <string>

using namespace std::string_literals;
using std::experimental::string_view;

#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/types.h>

#include <glog/logging.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

#include "test-credentials.ipp"

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
struct base64_data : sor<plus<base64_char>, rep_min_max<0, 2, one<'='>>> {};

struct param_char : sor<ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct param_name : rep_min_max<1, 20, param_char> {};

struct param_vchar : not_one<'\t'> {};
struct param_val : rep_min_max<1, 200, param_vchar> {};

struct parameter : sor<param_name, seq<param_name, one<'='>, param_val>> {};

struct UPPER_ALPHA : range<'A', 'Z'> {};

struct mech_char : sor<UPPER_ALPHA, DIGIT, HYPHEN, UNDERSCORE> {};
struct sasl_mech : rep_min_max<1, 20, mech_char> {};

struct vers : seq<TAOCPP_PEGTL_STRING("VERSION"), HTAB, one<'1'>, HTAB, one<'1'>, LF> {};
struct mech : seq<TAOCPP_PEGTL_STRING("MECH"), HTAB, sasl_mech, star<seq<HTAB, parameter>>, LF> {};
struct spid : seq<TAOCPP_PEGTL_STRING("SPID"), HTAB, pid, LF> {};
struct cuid : seq<TAOCPP_PEGTL_STRING("CUID"), HTAB, pid, LF> {};
struct cook : seq<TAOCPP_PEGTL_STRING("COOKIE"), HTAB, cookie, LF> {};
struct done : seq<TAOCPP_PEGTL_STRING("DONE"), LF> {};

struct resp : seq<vers, star<mech>, spid, cuid, cook, done> {};

struct auth_ok : seq<TAOCPP_PEGTL_STRING("OK"), HTAB, id, star<seq<HTAB, parameter>>> {};
struct auth_cont : seq<TAOCPP_PEGTL_STRING("CONT"), HTAB, id, HTAB, base64_data> {};
struct auth_fail : seq<TAOCPP_PEGTL_STRING("FAIL"), HTAB, id, star<seq<HTAB, parameter>>> {};

struct auth_resp : sor<auth_ok, auth_cont, auth_fail> {};

// clang-format on

struct Context {
  uint32_t id;
  std::string cookie;
  std::string sasl_mech;
  std::vector<std::string> parameter;
  std::unordered_map<std::string, std::vector<std::string>> mech;

  enum class auth_response { none, ok, cont, fail };

  auth_response auth_resp = auth_response::none;
};

char const* as_cstr(Context::auth_response rsp)
{
  switch (rsp) {
  case Context::auth_response::none:
    return "none";
  case Context::auth_response::ok:
    return "ok";
  case Context::auth_response::cont:
    return "cont";
  case Context::auth_response::fail:
    return "fail";
  }
  return "** unknown **";
}

std::ostream& operator<<(std::ostream& os, Context::auth_response rsp)
{
  return os << as_cstr(rsp);
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
    ctx.parameter.push_back(in.string());
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
    ctx.mech[ctx.sasl_mech] = std::move(ctx.parameter);
    ctx.parameter.clear();
    ctx.sasl_mech.clear();
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
}

constexpr char const* defined_params[]{
    "anonymous",       "plaintext",   "dictionary", "active",
    "forward-secrecy", "mutual-auth", "private",
};

int main()
{
  auto fd = socket(AF_UNIX, SOCK_STREAM, 0);
  PCHECK(fd >= 0) << "socket failed";

  sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  auto socket_path = "/var/spool/postfix/private/auth";
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  PCHECK(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  // boost::iostreams::stream<SockBuffer> ios(fd, fd);
  boost::iostreams::stream<boost::iostreams::file_descriptor> ios(
      fd, boost::iostreams::close_handle);

  ios << "VERSION\t1\t1\n"
      << "CPID\t" << getpid() << "\n"
      << std::flush;

  dovecot::Context ctx;
  istream_input<eol::lf> in(ios, 8 * 1024, "sasl");
  if (!parse<dovecot::resp, dovecot::action>(in, ctx)) {
    LOG(WARNING) << "handshake response parse failed";
  }

  for (auto const& m : ctx.mech) {
    LOG(INFO) << m.first;
  }

  std::stringstream tok;
  tok << '\0' << test::username << '\0' << test::password;
  auto init = Base64::enc(tok.str());

  if (ctx.mech.find("PLAIN") != ctx.mech.end()) {
    uint32_t id = 0x12345678;

    ios << "AUTH" << '\t' << id;

    ios << "\tPLAIN";
    ios << "\tservice=SMTP";
    ios << "\tresp=" << init;

    ios << "\n" << std::flush;

    if (!parse<dovecot::auth_resp, dovecot::action>(in, ctx)) {
      LOG(WARNING) << "auth response parse failed";
    }

    CHECK_EQ(ctx.id, id);
    LOG(INFO) << "AUTH: " << ctx.auth_resp;
  }
}

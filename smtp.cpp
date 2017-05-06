#include "Session.hpp"

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;
using namespace tao::pegtl::alphabet;

namespace smtp {

struct ehlo : istring<e, h, l, o, ' '> {
};

struct quit : istring<q, u, i, t> {
};

struct sub_domain : plus<ALPHA> {
};

struct domain : list_must<sub_domain, string<'.'>> {
};

struct ehlo_cmd : seq<ehlo, domain, CRLF> {
};

struct quit_cmd : seq<quit, CRLF> {
};

struct any_cmd : sor<ehlo_cmd, quit_cmd> {
};

struct cmds : star<any_cmd> {
};

struct grammar : seq<cmds, eof> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<ehlo_cmd> {
  template <typename Input>
  static void apply(const Input& in, Session& session)
  {
    auto ln = in.string();
    // 5 is the length of "EHLO " and two more for the CRLF.
    auto dom = ln.substr(5, ln.length() - 7);

    std::cout << dom << '\n';
    session.ehlo(dom);
  }
};

template <>
struct action<quit_cmd> {
  template <typename Input>
  static void apply(const Input& in, Session& session)
  {
    std::cout << "quit\n";
    session.quit();
  }
};
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  // Don't wait for STARTTLS to fail if no cert.
  CHECK(boost::filesystem::exists(TLS::cert_path)) << "can't find cert file";

  Session session;
  session.greeting();

  session.in().unsetf(std::ios::skipws);

  istream_input<crlf_eol> in(session.in(), 1024, "session");

  try {
    parse<smtp::grammar, smtp::action>(in, session);
  }
  catch (parse_error const& e) {
    std::cout << e.what() << '\n';
    return 1;
  }
}

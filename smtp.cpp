#include "Session.hpp"

#include <tao/pegtl.hpp>

namespace smtp {

struct ehlo : tao::pegtl::istring<'E', 'H', 'L', 'O', ' '> {
};

struct domain : tao::pegtl::plus<tao::pegtl::alpha> {
};

struct crlf : tao::pegtl::string<'\r', '\n'> {
};

struct grammar : tao::pegtl::must<ehlo, domain, crlf, tao::pegtl::eof> {
};

template <typename Rule>
struct action : tao::pegtl::nothing<Rule> {
};

template <>
struct action<domain> {
  template <typename Input>
  static void apply(const Input& in, std::string& name)
  {
    name = in.string();
  }
};
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  Session session;
  session.greeting();

  session.in().unsetf(std::ios::skipws);

  std::string dom;

  tao::pegtl::istream_input<tao::pegtl::crlf_eol> in(session.in(), 1024,
                                                     "session");

  try {
    tao::pegtl::parse<smtp::grammar, smtp::action>(in, dom);
  }
  catch (tao::pegtl::parse_error const& e) {
    std::cout << e.what() << '\n';
    return 1;
  }

  std::cout << dom << '\n';
}

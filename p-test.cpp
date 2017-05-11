#include <iostream>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;
using namespace tao::pegtl::alphabet;

#include <glog/logging.h>

namespace smtp {

struct Ctx {
};

struct String : plus<sor<ALPHA, DIGIT>> {
};

struct baz : seq<TAOCPP_PEGTL_ISTRING("BAZ"), CRLF> {
};

struct foo : seq<TAOCPP_PEGTL_ISTRING("FOO"), opt<SP, String>, CRLF> {
};

struct bar : seq<TAOCPP_PEGTL_ISTRING("BAR "), String, CRLF> {
};

struct quit : seq<TAOCPP_PEGTL_ISTRING("QUIT"), CRLF> {
};

struct lng : seq<TAOCPP_PEGTL_ISTRING("SUPERLONGTHING"), CRLF> {
};

struct any_cmd : seq<sor<baz, foo, bar, quit, lng>, discard> {
};

struct cmds : plus<any_cmd> {
};

struct grammar : seq<cmds, eof> {
};

template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<foo> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    std::cout << "foo\n";
  }
};

template <>
struct action<bar> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    std::cout << "bar\n";
  }
};

template <>
struct action<baz> {
  template <typename Input>
  static void apply(const Input& in, Ctx& ctx)
  {
    std::cout << "baz\n";
  }
};

template <>
struct action<quit> {
  static void apply0(Ctx& ctx) { std::cout << "quit\n"; }
};
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  smtp::Ctx ctx;
  istream_input<crlf_eol> in(std::cin, 20, "cin");

  std::cout << "250 start\n";

  try {
    LOG(INFO) << "calling parse";
    parse<smtp::grammar, smtp::action>(in, ctx);
    LOG(INFO) << "parse return";
  }
  catch (parse_error const& e) {
    std::cout << e.what() << '\n';
    return 1;
  }
}

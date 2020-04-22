#include <iostream>
#include <istream>
#include <streambuf>
#include <string_view>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

std::string esc(std::string_view str)
{
  std::string ret;
  for (auto c : str) {
    switch (c) {
    case '\n': ret += "\\n"; break;
    case '\r': ret += "\\r"; break;
    default: ret += c;
    }
  }
  return ret;
}

struct membuf : std::streambuf {
  membuf(char const* base, size_t size)
  {
    auto const p = const_cast<char*>(base);
    this->setg(p, p, p + size);
  }
};

struct mystream : virtual membuf, std::istream {
  mystream(std::string_view s)
    : membuf(s.data(), s.length())
    , std::istream(static_cast<std::streambuf*>(this))
  {
  }

  virtual std::streamsize xsgetn(char* s, std::streamsize count)
  {
    auto const read = membuf::xsgetn(s, count);
    std::cout << "xsgetn(" << count << ") «" << esc(std::string_view(s, read))
              << "»\n";
    return read;
  }
};

namespace rules {
struct chunk_size : plus<DIGIT> {
};

struct bdat : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, CRLF> {
};

struct end_marker : TAO_PEGTL_ISTRING("LAST") {
};

struct bdat_last
  : seq<TAO_PEGTL_ISTRING("BDAT"), SP, chunk_size, SP, end_marker, CRLF> {
};

struct quit : seq<TAO_PEGTL_ISTRING("QUIT"), CRLF> {
};

struct anything_else : seq<star<not_one<'\n'>>, one<'\n'>> {
};

struct any_cmd : seq<sor<bdat, bdat_last, quit, anything_else>, discard> {
};

struct grammar : plus<any_cmd> {
};
} // namespace rules

namespace actions {
template <typename Rule>
struct action : nothing<Rule> {
};

template <>
struct action<rules::bdat> {
  template <typename Input>
  static void apply(Input const& in)
  {
    std::cout << "action<bdat> «" << esc(in.string()) << "»\n";
  }
};

template <>
struct action<rules::bdat_last> {
  template <typename Input>
  static void apply(Input const& in)
  {
    std::cout << "action<bdat_last> «" << esc(in.string()) << "»\n";
  }
};

template <>
struct action<rules::anything_else> {
  template <typename Input>
  static void apply(Input const& in)
  {
    std::cout << "action<anything_else> «" << esc(in.string()) << "»\n";
  }
};

template <>
struct action<rules::quit> {
  template <typename Input>
  static void apply(Input const& in)
  {
    std::cout << "QUIT\n";
  }
};
} // namespace actions

int main()
{
  auto constexpr data = "BDAT 28\r\n"
                        "ABCDEFGHIJKLNMOPQRSTUVWXYZ\r\n"
                        "BDAT 0 LAST\r\n"
                        "QUIT\r\n";

  mystream istream(data);

  istream_input<eol::crlf, 1> in{istream, 128, "input-stream"};

  return parse<rules::grammar, actions::action>(in) ? 0 : 1;
}

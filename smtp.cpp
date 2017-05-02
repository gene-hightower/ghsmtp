#include "Session.hpp"

#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/include/support_istream_iterator.hpp>

namespace spirit = boost::spirit;

namespace smtp {
namespace x3 = boost::spirit::x3;

template <typename Iterator>
bool parse(Iterator first, Iterator last, Session& session)
{
  bool r = parse(first, last,
                 //  Begin grammar
                 (x3::no_case[x3::lit("EHLO")] >> x3::lit("\r\n"))
                 //  End grammar
                 );
  return r && (first == last);
}
}

int main(int argc, char const* argv[])
{
  std::ios::sync_with_stdio(false);
  google::InitGoogleLogging(argv[0]);

  Session session;
  session.greeting();

  session.in().unsetf(std::ios::skipws);
  spirit::istream_iterator begin(session.in());
  spirit::istream_iterator end;

  return smtp::parse(begin, end, session) ? 0 : 1;
}

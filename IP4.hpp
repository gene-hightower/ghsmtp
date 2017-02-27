/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#ifndef IP4_DOT_HPP
#define IP4_DOT_HPP

#include <experimental/string_view>

#include <boost/xpressive/xpressive.hpp>

#include <glog/logging.h>

namespace IP4 {

inline boost::xpressive::cregex single_octet()
{
  using namespace boost::xpressive;

  // clang-format off
  return (as_xpr('2') >> '5' >> range('0', '5'))
         | ('2' >> range('0', '4') >> _d)
         | (range('0', '1') >> repeat<2>(_d))
         | repeat<1, 2>(_d);
  // clang-format on
}

inline bool is_address(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re = octet >> '.' >> octet >> '.' >> octet >> '.' >> octet;
  cmatch matches;
  return regex_match(addr.begin(), addr.end(), matches, re);
}

inline bool is_bracket_address(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re
      = '[' >> octet >> '.' >> octet >> '.' >> octet >> '.' >> octet >> ']';
  cmatch matches;
  return regex_match(addr.begin(), addr.end(), matches, re);
}

inline std::string reverse(std::experimental::string_view addr)
{
  using namespace boost::xpressive;

  auto octet = single_octet();
  cregex re = (s1 = octet) >> '.' >> (s2 = octet) >> '.' >> (s3 = octet) >> '.'
              >> (s4 = octet);
  cmatch matches;
  CHECK(regex_match(addr.begin(), addr.end(), matches, re))
      << "IP4::reverse called with bad dotted quad: " << addr;

  std::ostringstream reverse;
  for (int n = 4; n > 0; --n) {
    std::experimental::string_view octet(matches[n].first,
                                         matches[n].second - matches[n].first);
    reverse << octet << '.'; // and leave a trailing '.'
  }
  return reverse.str();
}
}

#endif // IP4_DOT_HPP

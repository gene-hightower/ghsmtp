/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

  return (as_xpr('2') >> '5' >> range('0', '5'))
         | ('2' >> range('0', '4') >> _d)
         | (range('0', '1') >> repeat<1, 2>(_d)) | repeat<1, 2>(_d);
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

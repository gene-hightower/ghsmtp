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

#include <boost/utility/string_ref.hpp>
#include <boost/xpressive/xpressive.hpp>

#include "Logging.hpp"

using namespace boost::xpressive;

namespace IP4 {

inline bool is_address(char const* addr)
{
  cregex octet = (as_xpr('2') >> '5' >> range('0', '5')) | ('2' >> range('0', '4') >> _d)
                 | (range('0', '1') >> repeat<1, 2>(_d)) | repeat<1, 2>(_d);
  cregex re = octet >> '.' >> octet >> '.' >> octet >> '.' >> octet;
  cmatch matches;
  return regex_match(addr, matches, re);
}

inline std::string reverse(char const* addr)
{
  cregex octet = (as_xpr('2') >> '5' >> range('0', '5')) | ('2' >> range('0', '4') >> _d)
                 | (range('0', '1') >> repeat<1, 2>(_d)) | repeat<1, 2>(_d);
  cregex re = (s1 = octet) >> '.' >> (s2 = octet) >> '.' >> (s3 = octet) >> '.' >> (s4 = octet);
  cmatch matches;
  CHECK(regex_match(addr, matches, re)) << "reverse_ip4 called with bad dotted quad: " << addr;

  std::ostringstream reverse;
  for (int n = 4; n > 0; --n) {
    boost::string_ref octet(matches[n].first, matches[n].second - matches[n].first);
    reverse << octet << '.'; // and leave a trailing '.'
  }
  return reverse.str();
}
}

#endif // IP4_DOT_HPP

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

#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include <boost/algorithm/string/predicate.hpp>
#include <experimental/string_view>

namespace Domain {

inline bool match(std::experimental::string_view a,
                  std::experimental::string_view b)
{
  if ((0 != a.length()) && ('.' == a.back())) {
    a.remove_suffix(1);
  }

  if ((0 != b.length()) && ('.' == b.back())) {
    b.remove_suffix(1);
  }

  return boost::iequals(a, b);
}
}

#endif // DOMAIN_DOT_HPP

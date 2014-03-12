/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

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

#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include <boost/algorithm/string/predicate.hpp>
#include <boost/utility/string_ref.hpp>

namespace Domain {

inline bool match(boost::string_ref a, boost::string_ref b)
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

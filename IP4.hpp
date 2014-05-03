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

#include <regex>

#include <boost/utility/string_ref.hpp>

#include "Logging.hpp"

namespace IP4 {

inline bool is_address(char const* addr)
{
#define OCTET                                                                  \
  "(?:"                                                                        \
  "(?:25[0-5])|"                                                               \
  "(?:2[0-4]\\d)|"                                                             \
  "(?:[0-1]\\d{1,2})|"                                                         \
  "(?:\\d{1,2})"                                                               \
  ")"
  constexpr char const* dotted_quad_spec =
      OCTET "\\." OCTET "\\." OCTET "\\." OCTET;

  std::regex dotted_quad_rx(dotted_quad_spec);
  std::cmatch matches;
  return std::regex_match(addr, matches, dotted_quad_rx);
}

inline std::string reverse(char const* addr)
{
#define OCTET_CAP "(" OCTET ")"
  constexpr char const* dotted_quad_cap_spec =
      OCTET_CAP "\\." OCTET_CAP "\\." OCTET_CAP "\\." OCTET_CAP;

  std::regex dotted_quad_rx(dotted_quad_cap_spec);
  std::cmatch matches;
  CHECK(std::regex_match(addr, matches, dotted_quad_rx))
      << "reverse_ip4 called with bad dotted quad: " << addr;

  std::ostringstream reverse;
  for (int n = 4; n > 0; --n) {
    boost::string_ref octet(matches[n].first,
                            matches[n].second - matches[n].first);
    reverse << octet << '.'; // and leave a trailing '.'
  }
  return reverse.str();
}
}

#endif // IP4_DOT_HPP

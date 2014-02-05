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

#ifndef MAILBOX_DOT_HPP
#define MAILBOX_DOT_HPP

#include <string>
#include <ostream>

#include <boost/algorithm/string/predicate.hpp>

class Mailbox {
public:
  Mailbox(std::string const& local_part, std::string const& domain)
    : local_part_(local_part)
    , domain_(domain)
  {
  }
  Mailbox()
  {
  }
  void clear()
  {
    local_part_.clear();
    domain_.clear();
  }
  bool domain_is(std::string const& domain) const
  {
    // Should I remove trailing '.' if any of the domains has one?
    return boost::iequals(domain_, domain);
  }
  bool local_part_is(std::string const& local_part) const
  {
    return local_part_ == local_part;
  }
  bool empty() const
  {
    return local_part_.empty() && domain_.empty();
  }

private:
  std::string local_part_;
  std::string domain_;

  friend std::ostream& operator<<(std::ostream& stream, Mailbox const& mb)
  {
    return stream << '<' << mb.local_part_ << '@' << mb.domain_ << '>';
  }

};

#endif // MAILBOX_DOT_HPP

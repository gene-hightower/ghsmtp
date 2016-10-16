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

#include <ostream>
#include <string>
#include <utility>

class Mailbox {
public:
  Mailbox() = default;
  Mailbox(std::string local_part, std::string domain)
    : local_part_{std::move(local_part)}
    , domain_{std::move(domain)}
  {
  }
  void clear()
  {
    local_part_.clear();
    domain_.clear();
  }
  std::string const& domain() const { return domain_; }
  std::string const& local_part() const { return local_part_; }
  bool empty() const { return local_part_.empty() && domain_.empty(); }
  operator std::string() const { return local_part() + "@" + domain(); }

private:
  std::string local_part_;
  std::string domain_;
};

inline std::ostream& operator<<(std::ostream& s, Mailbox const& mb)
{
  return s << mb.local_part() << '@' << mb.domain();
}

#endif // MAILBOX_DOT_HPP

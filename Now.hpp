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

#ifndef NOW_DOT_HPP
#define NOW_DOT_HPP

#include <sys/time.h>

#include <iostream>

#include <glog/logging.h>

class Now {
public:
  Now()
  {
    PCHECK(gettimeofday(&tv_, 0) == 0);
    tm my_tm;
    CHECK_NOTNULL(localtime_r(&tv_.tv_sec, &my_tm));
    CHECK_EQ(
        strftime(c_str_, sizeof c_str_, "%a, %d %b %Y %H:%M:%S %z", &my_tm),
        sizeof(c_str_) - 1);
  }
  time_t sec() const { return tv_.tv_sec; }
  suseconds_t usec() const { return tv_.tv_usec; }
  bool operator==(Now const& that) const
  {
    return (this->sec() == that.sec()) && (this->usec() == that.usec());
  }
  bool operator!=(Now const& that) const { return !(*this == that); }

private:
  timeval tv_;
  char c_str_[32]; // RFC 5322 date-time section 3.3.

  friend std::ostream& operator<<(std::ostream& s, Now const& now)
  {
    return s << now.c_str_;
  }
};

#endif // NOW_DOT_HPP

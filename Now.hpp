/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>
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

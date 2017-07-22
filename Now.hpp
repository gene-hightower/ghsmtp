#ifndef NOW_DOT_HPP
#define NOW_DOT_HPP

#include <sys/time.h>

#include <glog/logging.h>

class Now {
public:
  Now();

  auto sec() const { return tv_.tv_sec; }
  auto usec() const { return tv_.tv_usec; }
  const char* string() const { return c_str_; }

private:
  timeval tv_;
  char c_str_[32]; // RFC 5322 date-time section 3.3.

  friend std::ostream& operator<<(std::ostream& s, Now const& now)
  {
    return s << now.c_str_;
  }
};

inline Now::Now()
{
  PCHECK(gettimeofday(&tv_, 0) == 0);
  tm* ptm = CHECK_NOTNULL(localtime(&tv_.tv_sec));
  CHECK_EQ(strftime(c_str_, sizeof c_str_, "%a, %d %b %Y %H:%M:%S %z", ptm),
           sizeof(c_str_) - 1);
}

#endif // NOW_DOT_HPP

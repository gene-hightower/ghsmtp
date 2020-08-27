#ifndef SRS_DOT_HPP
#define SRS_DOT_HPP

#include <srs2.h> 

#include "SRS.ipp"

class SRS {
public:
  SRS()
    : srs_(srs_new())
  {
    add_secret(srs_secret);
  }
  ~SRS()
  {
    srs_free(srs_);
  }
  void add_secret(char const* secret)
  {
    srs_add_secret(srs_, secret);
  }

private:
  srs_t* srs_;
};

#endif // SRS_DOT_HPP

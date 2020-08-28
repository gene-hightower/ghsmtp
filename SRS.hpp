#ifndef SRS_DOT_HPP
#define SRS_DOT_HPP

#include <string>

typedef struct _srs_t srs_t;

class SRS {
public:
  SRS();
  ~SRS();

  std::string forward(char const* sender, char const* alias);
  std::string reverse(char const* sender);

  void add_secret(char const* secret);

private:
  srs_t* srs_;
};

#endif // SRS_DOT_HPP

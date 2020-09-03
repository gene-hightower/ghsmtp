#ifndef OPENDMARC_DOT_HPP
#define OPENDMARC_DOT_HPP

#include "IP6.hpp"

#include <opendmarc/dmarc.h>

#include <glog/logging.h>

namespace OpenDMARC {

enum class Advice;
constexpr char const* Advice_to_string(Advice adv);

class Lib {
  Lib(Lib const&) = delete;
  Lib& operator=(Lib const&) = delete;

public:
  Lib();
  ~Lib();

private:
  OPENDMARC_LIB_T lib_;
};

class Policy {
public:
  Policy()              = default;
  Policy(Policy const&) = delete;
  Policy& operator=(Policy const&) = delete;

  ~Policy();

  void   init(char const* ip);
  bool   store_from_domain(char const* from_domain);
  bool   store_dkim(char const* d_equal_domain,
                    int         dkim_result,
                    char const* human_result);
  bool   store_spf(char const* domain,
                   int         result,
                   int         origin,
                   char const* human_readable);
  bool   query_dmarc(char const* domain);
  Advice get_advice();

private:
  DMARC_POLICY_T* pctx_{nullptr};
};

enum class Advice {
  ACCEPT,
  REJECT,
  QUARANTINE,
  NONE,
};

constexpr char const* Advice_to_string(Advice adv)
{
  switch (adv) {
  case Advice::ACCEPT: return "accept";
  case Advice::REJECT: return "reject";
  case Advice::QUARANTINE: return "quarantine";
  case Advice::NONE: break;
  }
  return "none";
}

} // namespace OpenDMARC

#endif // OPENDMARC_DOT_HPP

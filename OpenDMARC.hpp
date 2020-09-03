#ifndef OPENDMARC_DOT_HPP
#define OPENDMARC_DOT_HPP

#include "IP6.hpp"

#include <opendmarc/dmarc.h>

#include <glog/logging.h>

namespace OpenDMARC {

enum class advice;
constexpr char const* advice_to_string(advice adv);

class lib {
  // no copy
  lib(lib const&) = delete;
  lib& operator=(lib const&) = delete;

public:
  // move
  lib(lib&&)   = default;
  lib& operator=(lib&&) = default;

  lib();
  ~lib();

private:
  OPENDMARC_LIB_T lib_;
};

class policy {
  // no copy
  policy(policy const&) = delete;
  policy& operator=(policy const&) = delete;

public:
  policy() = default;

  // move
  policy(policy&&) = default;
  policy& operator=(policy&&) = default;

  ~policy();

  void   connect(char const* ip);
  bool   store_from_domain(char const* from_domain);
  bool   store_dkim(char const* d_equal_domain,
                    int         dkim_result,
                    char const* human_result);
  bool   store_spf(char const* domain,
                   int         result,
                   int         origin,
                   char const* human_readable);
  bool   query_dmarc(char const* domain);
  advice get_advice();

private:
  DMARC_POLICY_T* pctx_{nullptr};
};

enum class advice {
  ACCEPT,
  REJECT,
  QUARANTINE,
  NONE,
};

constexpr char const* advice_to_string(advice adv)
{
  switch (adv) {
  case advice::ACCEPT: return "accept";
  case advice::REJECT: return "reject";
  case advice::QUARANTINE: return "quarantine";
  case advice::NONE: break;
  }
  return "none";
}

} // namespace OpenDMARC

#endif // OPENDMARC_DOT_HPP

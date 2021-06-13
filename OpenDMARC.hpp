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
                    char const* d_selector,
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

constexpr char const* policy_spf_to_string(int pol)
{
  switch (pol) {
  case DMARC_POLICY_SPF_OUTCOME_NONE: return "SPF_OUTCOME_NONE";
  case DMARC_POLICY_SPF_OUTCOME_PASS: return "SPF_OUTCOME_PASS";
  case DMARC_POLICY_SPF_OUTCOME_FAIL: return "SPF_OUTCOME_FAIL";
  case DMARC_POLICY_SPF_OUTCOME_TMPFAIL: return "SPF_OUTCOME_TMPFAIL";
  case DMARC_POLICY_SPF_ALIGNMENT_PASS: return "SPF_ALIGNMENT_PASS";
  case DMARC_POLICY_SPF_ALIGNMENT_FAIL: return "SPF_ALIGNMENT_FAIL";
  }
  return "none";
}

} // namespace OpenDMARC

#endif // OPENDMARC_DOT_HPP

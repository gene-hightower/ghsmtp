#ifndef DMARC_DOT_HPP
#define DMARC_DOT_HPP

#include "IP6.hpp"

#include <opendmarc/dmarc.h>

#include <glog/logging.h>

namespace OpenDMARC {

enum class Advice;
auto constexpr Advice_to_string(Advice adv) -> char const*;

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
  Policy() = default;
  Policy(Policy const&) = delete;
  Policy& operator=(Policy const&) = delete;

  ~Policy();

  auto init(char const* ip) -> void;
  auto store_from_domain(char const* from_domain) -> bool;
  auto store_dkim(char const* d_equal_domain,
                  int dkim_result,
                  char const* human_result) -> bool;
  auto store_spf(char const* domain,
                 int result,
                 int origin,
                 char const* human_readable) -> bool;
  auto query_dmarc(char const* domain) -> bool;
  auto get_advice() -> Advice;

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
  case Advice::ACCEPT:
    return "accept";

  case Advice::REJECT:
    return "reject";

  case Advice::QUARANTINE:
    return "quarantine";

  case Advice::NONE:
    break;
  }
  return "none";
}

} // namespace OpenDMARC

#endif // DMARC_DOT_HPP

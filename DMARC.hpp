#ifndef DMARC_DOT_HPP
#define DMARC_DOT_HPP

#include <opendmarc/dmarc.h>

#include <glog/logging.h>

#include "stringify.h"

namespace OpenDMARC {

constexpr u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>((cp)));
}

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

class Lib {
public:
  Lib()
  {
    lib_.tld_type = OPENDMARC_TLD_TYPE_MOZILLA;
    constexpr auto cert_path = STRINGIFY(SMTP_HOME) "/public_suffix_list.dat";
    CHECK_LT(strlen(cert_path), MAXPATHLEN);
    strncpy(reinterpret_cast<char*>(lib_.tld_source_file), cert_path,
            MAXPATHLEN);
    auto status = opendmarc_policy_library_init(&lib_);
    CHECK_EQ(status, DMARC_PARSE_OKAY)
        << opendmarc_policy_status_to_str(status);
  }

  ~Lib() { opendmarc_policy_library_shutdown(&lib_); }

private:
  OPENDMARC_LIB_T lib_;
};

class Policy {
public:
  ~Policy()
  {
    if (pctx_) {
      opendmarc_policy_connect_shutdown(pctx_);
      pctx_ = nullptr;
    }
  }

  void init(char const* ip4)
  {
    pctx_ = CHECK_NOTNULL(opendmarc_policy_connect_init(uc(ip4), false));
  }

  bool store_from_domain(char const* from_domain)
  {
    auto status = opendmarc_policy_store_from_domain(pctx_, uc(from_domain));
    if (status != DMARC_PARSE_OKAY) {
      LOG(ERROR) << "from_domain == " << from_domain;
      LOG(ERROR) << opendmarc_policy_status_to_str(status);
      return false;
    }
    return true;
  }

  bool store_dkim(char const* d_equal_domain,
                  int dkim_result,
                  char const* human_result)
  {
    auto status = opendmarc_policy_store_dkim(pctx_, uc(d_equal_domain),
                                              dkim_result, uc(human_result));
    if (status != DMARC_PARSE_OKAY) {
      LOG(ERROR) << "d_equal_domain == " << d_equal_domain;
      LOG(ERROR) << opendmarc_policy_status_to_str(status);
      return false;
    }
    return true;
  }

  bool store_spf(char const* domain,
                 int result,
                 int origin,
                 char const* human_readable)
  {
    auto status = opendmarc_policy_store_spf(pctx_, uc(domain), result, origin,
                                             uc(human_readable));
    if (status != DMARC_PARSE_OKAY) {
      LOG(ERROR) << "domain == " << domain;
      LOG(ERROR) << opendmarc_policy_status_to_str(status);
      return false;
    }
    return true;
  }

  bool query_dmarc(char const* domain)
  {
    auto status = opendmarc_policy_query_dmarc(pctx_, uc(domain));
    if (status != DMARC_PARSE_OKAY) {
      LOG(ERROR) << "domain == " << domain;
      LOG(ERROR) << opendmarc_policy_status_to_str(status);
      return false;
    }
    return true;
  }

  Advice get_policy()
  {
    auto status = opendmarc_get_policy_to_enforce(pctx_);

    switch (status) {
    case DMARC_PARSE_ERROR_NULL_CTX:
      LOG(FATAL) << "NULL pctx value";

    case DMARC_FROM_DOMAIN_ABSENT:
      LOG(FATAL) << "No From: domain";

    case DMARC_POLICY_ABSENT:
      return Advice::NONE;

    case DMARC_POLICY_PASS:
      return Advice::ACCEPT;

    case DMARC_POLICY_REJECT:
      return Advice::REJECT;

    case DMARC_POLICY_QUARANTINE:
      return Advice::QUARANTINE;

    case DMARC_POLICY_NONE:
      return Advice::NONE;
    }

    LOG(FATAL) << "unknown status";
  }

private:
  DMARC_POLICY_T* pctx_{nullptr};
};
}

#endif // DMARC_DOT_HPP

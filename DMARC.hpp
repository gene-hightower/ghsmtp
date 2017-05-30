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

class Lib {
public:
  Lib()
  {
    lib_.tld_type = OPENDMARC_TLD_TYPE_MOZILLA;
    constexpr auto cert_path = STRINGIFY(SMTP_HOME) "/public_suffix_list.dat";
    strncpy(reinterpret_cast<char*>(lib_.tld_source_file), cert_path,
            MAXPATHLEN);

    CHECK_EQ(opendmarc_policy_library_init(&lib_), DMARC_PARSE_OKAY);
  }
  ~Lib()
  {
    CHECK_EQ(opendmarc_policy_library_shutdown(&lib_), DMARC_PARSE_OKAY);
  }

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

  void store_from_domain(char const* from_domain)
  {
    auto status = opendmarc_policy_store_from_domain(pctx_, uc(from_domain));
    if (status != DMARC_PARSE_OKAY) {
      LOG(ERROR) << "from_domain == " << from_domain;

      // ??
      if (status == DMARC_PARSE_ERROR_NO_DOMAIN) {
        LOG(ERROR) << "DMARC_PARSE_ERROR_NO_DOMAIN";
      }
      if (status == DMARC_PARSE_ERROR_NO_REQUIRED_P) {
        LOG(ERROR) << "DMARC_PARSE_ERROR_NO_REQUIRED_P";
      }

      char bfr[256];
      opendmarc_policy_to_buf(pctx_, bfr, sizeof(bfr));

      LOG(ERROR) << bfr;
    }
  }

  void store_dkim(char const* d_equal_domain,
                  int dkim_result,
                  char const* human_result)
  {
    LOG(INFO) << "d_equal_domain == " << d_equal_domain;

    CHECK_EQ(opendmarc_policy_store_dkim(pctx_, uc(d_equal_domain), dkim_result,
                                         uc(human_result)),
             DMARC_PARSE_OKAY);
  }

  void store_spf(char const* domain,
                 int result,
                 int origin,
                 char const* human_readable)
  {
    CHECK_EQ(opendmarc_policy_store_spf(pctx_, uc(domain), result, origin,
                                        uc(human_readable)),
             DMARC_PARSE_OKAY);
  }

  void query_dmarc(char const* domain)
  {
    auto ret = opendmarc_policy_query_dmarc(pctx_, uc(domain));

    switch (ret) {
    case DMARC_PARSE_OKAY:
      LOG(INFO) << "parse okay";
      break;

    case DMARC_PARSE_ERROR_NULL_CTX:
      LOG(FATAL) << "null ctx";

    case DMARC_PARSE_ERROR_EMPTY:
      LOG(FATAL) << "error empty";

    case DMARC_PARSE_ERROR_NO_DOMAIN:
      LOG(FATAL) << "no domain";

    case DMARC_DNS_ERROR_NXDOMAIN:
      LOG(INFO) << "No such domain found in DNS.";
      break;

    case DMARC_DNS_ERROR_TMPERR:
      LOG(INFO) << "DNS returned a temporary failure.";
      break;

    case DMARC_DNS_ERROR_NO_RECORD:
      LOG(INFO) << "The domain exists but no DMARC record was found, either at"
                   " that domain or a found organizational domain.";
      break;

    case DMARC_PARSE_ERROR_BAD_VERSION:
      LOG(WARNING) << "If the DMARC record's v= was bad.";
      break;

    case DMARC_PARSE_ERROR_BAD_VALUE:
      LOG(WARNING) << "If a value following an = was bad or illegal.";
      break;

    case DMARC_PARSE_ERROR_NO_REQUIRED_P:
      LOG(WARNING) << "The required p= was absent.";
      break;

    default:
      LOG(INFO) << "unknown return value from opendmarc_policy_query_dmarc()";
      break;
    }
  }

private:
  DMARC_POLICY_T* pctx_{nullptr};
};
}

#endif // DMARC_DOT_HPP

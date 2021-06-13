#include "OpenDMARC.hpp"

#include "osutil.hpp"

namespace {
u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>((cp)));
}
} // namespace

namespace OpenDMARC {
lib::lib()
{
#define PUBLIC_SUFFIX_LIST_DAT "public_suffix_list.dat"
  auto const path{[] {
    auto const our_list{osutil::get_config_dir() / PUBLIC_SUFFIX_LIST_DAT};
    if (fs::exists(our_list))
      return our_list;

    auto const sys_list{
        fs::path{"/usr/share/publicsuffix/" PUBLIC_SUFFIX_LIST_DAT}};
    if (fs::exists(sys_list))
      return sys_list;

    LOG(FATAL) << "can't find " PUBLIC_SUFFIX_LIST_DAT;
  }()};

  lib_ = {.tld_type = OPENDMARC_TLD_TYPE_MOZILLA};

  CHECK_LT(path.string().length(), sizeof(lib_.tld_source_file));
  strcpy(reinterpret_cast<char*>(lib_.tld_source_file), path.string().c_str());

  auto const status = opendmarc_policy_library_init(&lib_);
  CHECK_EQ(status, DMARC_PARSE_OKAY) << opendmarc_policy_status_to_str(status);
}

lib::~lib() { opendmarc_policy_library_shutdown(&lib_); }

policy::~policy()
{
  if (pctx_) {
    opendmarc_policy_connect_shutdown(pctx_);
    pctx_ = nullptr;
  }
}

void policy::connect(char const* ip)
{
  CHECK_NOTNULL(ip);
  auto const is_ipv6 = IP6::is_address(ip);
  pctx_ = CHECK_NOTNULL(opendmarc_policy_connect_init(uc(ip), is_ipv6));
}

bool policy::store_from_domain(char const* from_domain)
{
  CHECK_NOTNULL(from_domain);
  auto const status =
      opendmarc_policy_store_from_domain(pctx_, uc(from_domain));
  if (status != DMARC_PARSE_OKAY) {
    LOG(WARNING) << "from_domain == " << from_domain;
    LOG(WARNING) << opendmarc_policy_status_to_str(status);
    return false;
  }
  return true;
}

bool policy::store_dkim(char const* d_equal_domain,
                        char const* d_selector,
                        int         dkim_result,
                        char const* human_result)
{
  CHECK_NOTNULL(d_equal_domain);
  CHECK_NOTNULL(human_result);
  LOG(INFO) << "d_equal_domain == " << d_equal_domain;
  auto const status = opendmarc_policy_store_dkim(
      pctx_, uc(d_selector), uc(d_equal_domain), dkim_result, uc(human_result));
  if (status != DMARC_PARSE_OKAY) {
    LOG(WARNING) << "d_equal_domain == " << d_equal_domain;
    LOG(WARNING) << opendmarc_policy_status_to_str(status);
    return false;
  }
  return true;
}

bool policy::store_spf(char const* domain,
                       int         result,
                       int         origin,
                       char const* human_readable)
{
  CHECK_NOTNULL(domain);
  CHECK_NOTNULL(human_readable);
  auto const status = opendmarc_policy_store_spf(pctx_, uc(domain), result,
                                                 origin, uc(human_readable));
  if (status != DMARC_PARSE_OKAY) {
    LOG(WARNING) << "domain == " << domain;
    LOG(WARNING) << opendmarc_policy_status_to_str(status);
    return false;
  }
  return true;
}

bool policy::query_dmarc(char const* domain)
{
  CHECK_NOTNULL(domain);
  auto const status = opendmarc_policy_query_dmarc(pctx_, uc(domain));
  if (status != DMARC_PARSE_OKAY) {
    LOG(WARNING) << domain << ": " << opendmarc_policy_status_to_str(status);
    return false;
  }
  return true;
}

advice policy::get_advice()
{
  auto const status = opendmarc_get_policy_to_enforce(pctx_);

  switch (status) {
  case DMARC_PARSE_ERROR_NULL_CTX:
    LOG(WARNING) << "NULL pctx value";
    return advice::NONE;

  case DMARC_FROM_DOMAIN_ABSENT:
    LOG(WARNING) << "no From: domain";
    return advice::NONE;

  case DMARC_POLICY_ABSENT: return advice::NONE;
  case DMARC_POLICY_PASS: return advice::ACCEPT;
  case DMARC_POLICY_REJECT: return advice::REJECT;
  case DMARC_POLICY_QUARANTINE: return advice::QUARANTINE;
  case DMARC_POLICY_NONE: return advice::NONE;
  }

  LOG(FATAL) << "unknown status";
}

} // namespace OpenDMARC

#include "SPF.hpp"

#include "IP4.hpp"
#include "IP6.hpp"

namespace SPF {

char const* as_cstr(Result result)
{
  switch (result) {
  case Result::INVALID:
    return "invalid";
  case Result::NEUTRAL:
    return "neutral";
  case Result::PASS:
    return "pass";
  case Result::FAIL:
    return "fail";
  case Result::SOFTFAIL:
    return "softfail";
  case Result::NONE:
    return "none";
  case Result::TEMPERROR:
    return "temperror";
  case Result::PERMERROR:
    return "permerror";
  }
  return "Unknown";
}

std::ostream& operator<<(std::ostream& os, Result result)
{
  return os << as_cstr(result);
}

// We map libspf2's levels of error, warning, info and debug to our
// own fatal, error, warning and info log levels.

static void log_error(const char* file, int line, char const* errmsg)
    __attribute__((noreturn));
static void log_error(const char* file, int line, char const* errmsg)
{
  LOG(FATAL) << file << ":" << line << " " << errmsg;
}
static void log_warning(const char* file, int line, char const* errmsg)
{
  LOG(ERROR) << file << ":" << line << " " << errmsg;
}
static void log_info(const char* file, int line, char const* errmsg)
{
  LOG(WARNING) << file << ":" << line << " " << errmsg;
}

void Request::set_ip_str(char const* ip)
{
  if (IP4::is_address(ip)) {
    set_ipv4_str(ip);
  }
  else if (IP6::is_address(ip)) {
    set_ipv6_str(ip);
  }
  else {
    LOG(FATAL) << "non IP address passwd to set_ip_str: " << ip;
  }
}

struct Init {
  Init()
  {
    SPF_error_handler = log_error;
    SPF_warning_handler = log_warning;
    SPF_info_handler = log_info;
    SPF_debug_handler = nullptr;
  }
};

static Init init;
}

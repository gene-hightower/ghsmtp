#include "SPF.hpp"

namespace SPF {

std::ostream& operator<<(std::ostream& os, Result result)
{
  switch (result) {
  case Result::INVALID:
    return os << "INVALID";
  case Result::NEUTRAL:
    return os << "NEUTRAL";
  case Result::PASS:
    return os << "PASS";
  case Result::FAIL:
    return os << "FAIL";
  case Result::SOFTFAIL:
    return os << "SOFTFAIL";
  case Result::NONE:
    return os << "NONE";
  case Result::TEMPERROR:
    return os << "TEMPERROR";
  case Result::PERMERROR:
    return os << "PERMERROR";
  }
  return os << "Unknown";
}

// We map libspf2's levels of error, warning, info and debug to our
// own fatal, error, warning and info log levels.

static void log_error(const char* file, int line, char const* errmsg) __attribute__((noreturn));
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

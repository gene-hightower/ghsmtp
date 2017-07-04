#include "hostname.hpp"

#include <sys/utsname.h>

#include <glog/logging.h>

std::string get_hostname()
{
  utsname un;
  PCHECK(uname(&un) == 0);
  return std::string(un.nodename);
}

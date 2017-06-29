#ifndef IP6_DOT_HPP
#define IP6_DOT_HPP

#include <experimental/string_view>

#include <glog/logging.h>

namespace IP6 {

inline bool is_address(std::experimental::string_view addr)
{
  return false;
}

inline bool is_address_literal(std::experimental::string_view addr)
{
  return false;
}

inline std::string reverse(std::experimental::string_view addr)
{
  LOG(FATAL) << "can't reverse IPv6 address yet";
  return "";
}
}

#endif // IP4_DOT_HPP

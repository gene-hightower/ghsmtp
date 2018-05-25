#ifndef DNS_FCRDNS_DOT_HPP_INCLUDED
#define DNS_FCRDNS_DOT_HPP_INCLUDED

#include "DNS-priv.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace DNS {
std::vector<std::string> fcrdns4(Resolver& res, std::string_view addr);
std::vector<std::string> fcrdns6(Resolver& res, std::string_view addr);
std::vector<std::string> fcrdns(Resolver& res, std::string_view addr);
} // namespace DNS

#endif // DNS_FCRDNS_DOT_HPP_INCLUDED

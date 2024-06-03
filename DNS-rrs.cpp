#include "DNS-rrs.hpp"

#include "DNS-iostream.hpp"

#include <cstring>

#include <arpa/inet.h>

#include <glog/logging.h>

namespace DNS {

RR_A::RR_A(uint8_t const* rd, size_t sz)
{
  static_assert(sizeof(addr_.sin_addr) == 4);
  CHECK_EQ(sz, sizeof(addr_.sin_addr));
  std::memcpy(&addr_.sin_addr, rd, sizeof(addr_.sin_addr));
  PCHECK(inet_ntop(AF_INET, &addr_.sin_addr, str_, sizeof str_));
}

RR_AAAA::RR_AAAA(uint8_t const* rd, size_t sz)
{
  static_assert(sizeof(addr_.sin6_addr) == 16);
  CHECK_EQ(sz, sizeof(addr_.sin6_addr));
  std::memcpy(&addr_.sin6_addr, rd, sizeof(addr_.sin6_addr));
  PCHECK(inet_ntop(AF_INET6, &addr_.sin6_addr, str_, sizeof str_));
}

RR_TLSA::RR_TLSA(uint8_t                cert_usage,
                 uint8_t                selector,
                 uint8_t                matching_type,
                 std::span<octet const> data)
  : cert_usage_(cert_usage)
  , selector_(selector)
  , matching_type_(matching_type)
{
  assoc_data_.resize(data.size());
  std::memcpy(assoc_data_.data(), data.data(), data.size());
}

} // namespace DNS

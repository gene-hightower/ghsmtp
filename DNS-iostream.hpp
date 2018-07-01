#ifndef DNS_IOSTREAM_DOT_HPP
#define DNS_IOSTREAM_DOT_HPP

#include "DNS-rrs.hpp"

#include <iostream>

inline std::ostream& operator<<(std::ostream& os, DNS::RR_A const& rr_a)
{
  return os << "A " << rr_a.c_str();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_CNAME const& rr_c)
{
  return os << "CNAME " << rr_c.str();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_PTR const& rr_ptr)
{
  return os << "PTR " << rr_ptr.str();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_MX const& rr_mx)
{
  return os << "MX " << rr_mx.preference() << ' ' << rr_mx.exchange();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_TXT const& rr_txt)
{
  return os << "TXT " << rr_txt.str();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_AAAA const& rr_aaaa)
{
  return os << "AAAA " << rr_aaaa.c_str();
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_TLSA const& rr_tlsa)
{
  os << "TLSA " << rr_tlsa.cert_usage() << ' ' << rr_tlsa.selector() << ' '
     << rr_tlsa.matching_type() << ' ';

  for (auto const ch : rr_tlsa.assoc_data()) {
    auto const lo = ch & 0xF;
    auto const hi = (ch >> 4) & 0xF;

    auto constexpr hex_digits = "0123456789abcdef";

    os << hex_digits[hi] << hex_digits[lo];
  }

  return os;
}

inline std::ostream& operator<<(std::ostream& os, DNS::RR_type const& type)
{
  return os << DNS::RR_type_c_str(type);
}

#endif // DNS_IOSTREAM_DOT_HPP

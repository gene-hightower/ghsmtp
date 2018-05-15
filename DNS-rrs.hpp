#ifndef DNS_RRS_DOT_HPP
#define DNS_RRS_DOT_HPP

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

#include <netinet/in.h>

namespace DNS {

enum class RR_type : uint16_t {
  // RFC 1035 section 3.2.2 “TYPE values”
  NONE,
  A,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  RR_NULL,
  WKS,
  PTR,
  HINFO,
  MINFO,
  MX,
  TXT,

  // RFC 3596 section 2.1 “AAAA record type”
  AAAA = 28,

  // RFC 6698 section 7.1 “TLSA RRtype”
  TLSA = 52,
};

constexpr char const* RR_type_c_str(RR_type type)
{
  switch (type) { // clang-format off
  case RR_type::NONE:   return "NONE";
  case RR_type::A:      return "A";
  case RR_type::NS:     return "NS";
  case RR_type::MD:     return "MD";
  case RR_type::MF:     return "MF";
  case RR_type::CNAME:  return "CNAME";
  case RR_type::SOA:    return "SOA";
  case RR_type::MB:     return "MB";
  case RR_type::MG:     return "MG";
  case RR_type::MR:     return "MR";
  case RR_type::RR_NULL:return "RR_NULL";
  case RR_type::WKS:    return "WKS";
  case RR_type::PTR:    return "PTR";
  case RR_type::HINFO:  return "HINFO";
  case RR_type::MINFO:  return "MINFO";
  case RR_type::MX:     return "MX";
  case RR_type::TXT:    return "TXT";
  case RR_type::AAAA:   return "AAAA";
  case RR_type::TLSA:   return "TLSA";
  } // clang-format on
  return "*** unknown RR_type ***";
}

constexpr char const* rcode_c_str(uint16_t rcode)
{
  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
  switch (rcode) { // clang-format off
  case 0:  return "no error";                           // [RFC1035]
  case 1:  return "format error";                       // [RFC1035]
  case 2:  return "server failure";                     // [RFC1035]
  case 3:  return "non-existent domain";                // [RFC1035]
  case 4:  return "not implemented";                    // [RFC1035]
  case 5:  return "query Refused";                      // [RFC1035]
  case 6:  return "name exists when it should not";     // [RFC2136][RFC6672]
  case 7:  return "RR set exists when it should not";   // [RFC2136]
  case 8:  return "RR set that should exist does not";  // [RFC2136]
  case 9:  return "server not authoritative for zone or not authorized"; // [RFC2136 & RFC2845]
  case 10: return "name not contained in zone";         // [RFC2136]
  case 11: return "unassigned-11";
  case 12: return "unassigned-12";
  case 13: return "unassigned-13";
  case 14: return "unassigned-14";
  case 15: return "unassigned-15";
  case 16: return "bad OPT version or TSIG signature failure"; // [RFC6891 & RFC2845]
  case 17: return "key not recognized";                 // [RFC2845]
  case 18: return "signature out of time window";       // [RFC2845]
  case 19: return "bad TKEY mode";                      // [RFC2930]
  case 20: return "duplicate key name";                 // [RFC2930]
  case 21: return "algorithm not supported";            // [RFC2930]
  case 22: return "bad truncation";                     // [RFC4635]
  case 23: return "bad/missing server cookie";          // [RFC7873]
  } // clang-format on
  if ((24 <= rcode) && (rcode <= 3840)) {
    return "unassigned-24-3840";
  }
  if ((3841 <= rcode) && (rcode <= 4095)) {
    return "reserved for private use"; // [RFC6895]
  }
  if ((4096 <= rcode) && (rcode <= 65534)) {
    return "unassigned-4096-65534";
  }
  if (rcode == 65535) {
    return "reserved-65535"; // [RFC6895]
  }
  return "*** rcode out of range ***";
}

class RR_A {
public:
  RR_A(uint8_t const* rd, size_t sz);

  sockaddr_in const& addr() const { return addr_; }
  char const* c_str() const { return str_; }

private:
  sockaddr_in addr_;
  char str_[INET_ADDRSTRLEN];
};

class RR_CNAME {
public:
  explicit RR_CNAME(std::string cname)
    : cname_(cname)
  {
  }

  std::string const& str() const { return cname_; }
  char const* c_str() const { return str().c_str(); }

private:
  std::string cname_;
};

// RFC 2181 section 10.2 PTR records
class RR_PTR {
public:
  explicit RR_PTR(std::string ptrdname)
    : ptrdname_(ptrdname)
  {
  }

  std::string const& str() const { return ptrdname_; }
  char const* c_str() const { return str().c_str(); }

private:
  std::string ptrdname_;
};

class RR_MX {
public:
  RR_MX(std::string exchange, uint16_t preference)
    : exchange_(exchange)
    , preference_(preference)
  {
  }

  std::string const& exchange() const { return exchange_; }
  uint16_t preference() const { return preference_; }

private:
  std::string exchange_;
  uint16_t preference_;
};

class RR_TXT {
public:
  explicit RR_TXT(std::string txt_data)
    : txt_data_(txt_data)
  {
  }

  std::string const& str() const { return txt_data_; }
  char const* c_str() const { return str().c_str(); }

private:
  std::string txt_data_;
};

class RR_AAAA {
public:
  RR_AAAA(uint8_t const* rd, size_t sz);

  sockaddr_in6 const& addr() const { return addr_; }
  char const* c_str() const { return str_; }

private:
  sockaddr_in6 addr_;
  char str_[INET6_ADDRSTRLEN];
};

class RR_TLSA {
public:
  RR_TLSA(uint8_t cert_usage,
          uint8_t selector,
          uint8_t matching_type,
          uint8_t const* assoc_data,
          size_t assoc_data_sz);
  unsigned cert_usage() const { return cert_usage_; }
  unsigned selector() const { return selector_; }
  unsigned matching_type() const { return matching_type_; }
  std::vector<unsigned char> const& assoc_data() const { return assoc_data_; }

private:
  std::vector<unsigned char> assoc_data_;
  uint8_t cert_usage_;
  uint8_t selector_;
  uint8_t matching_type_;
};

using RR
    = std::variant<RR_A, RR_CNAME, RR_PTR, RR_MX, RR_TXT, RR_AAAA, RR_TLSA>;

using RR_set = std::vector<RR>;

}

#endif // DNS_RRS_DOT_HPP
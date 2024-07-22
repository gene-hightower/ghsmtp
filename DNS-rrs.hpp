#ifndef DNS_RRS_DOT_HPP
#define DNS_RRS_DOT_HPP

#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include <netinet/in.h>

#include "iobuffer.hpp"

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
  RP,    // RFC 1183 Responsible Person
  AFSDB, // RFC 1183 AFS database record

  // RFC 2535
  SIG = 24, // RFC 2535 Signature
  KEY = 25, // RFC 2535 and RFC 2930 Key record

  // RFC 3596 section 2.1 “AAAA record type”
  AAAA = 28,

  // RFC 2782 Service locator
  SRV = 33,

  // RFC 4398 Certificate record
  CERT = 37,

  // RFC 6891 EDNS(0) OPT pseudo-RR
  OPT = 41,

  // RFC 4255 SSH Public Key Fingerprint
  SSHFP = 44,

  // RFC 4034
  RRSIG  = 46, // DNSSEC signature
  NSEC   = 47, // Next Secure record
  DNSKEY = 48, // DNS Key record

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
  case RR_type::RP:     return "RP";
  case RR_type::AFSDB:  return "AFSDB";
  case RR_type::SIG:    return "SIG";
  case RR_type::KEY:    return "KEY";
  case RR_type::AAAA:   return "AAAA";
  case RR_type::SRV:    return "SRV";
  case RR_type::CERT:   return "CERT";
  case RR_type::OPT:    return "OPT";
  case RR_type::SSHFP:  return "SSHFP";
  case RR_type::RRSIG:  return "RRSIG";
  case RR_type::NSEC:   return "NSEC";
  case RR_type::DNSKEY: return "DNSKEY";
  case RR_type::TLSA:   return "TLSA";
  } // clang-format on
  return "*** unknown RR_type ***";
}

constexpr char const* RR_type_c_str(uint16_t rcode)
{
  return RR_type_c_str(static_cast<RR_type>(rcode));
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

  std::optional<std::string> as_str() const { return std::string{str_}; }

  sockaddr_in const& addr() const { return addr_; }
  char const*        c_str() const { return str_; }
  constexpr static RR_type rr_type() { return RR_type::A; }

  bool operator==(RR_A const& rhs) const { return strcmp(str_, rhs.str_) == 0; }
  bool operator<(RR_A const& rhs) const { return strcmp(str_, rhs.str_) < 0; }

private:
  sockaddr_in addr_;
  char        str_[INET_ADDRSTRLEN];
};

class RR_CNAME {
public:
  explicit RR_CNAME(std::string cname)
    : cname_(cname)
  {
  }

  std::optional<std::string> as_str() const { return str(); }

  std::string const& str() const { return cname_; }
  char const*        c_str() const { return str().c_str(); }
  constexpr static RR_type rr_type() { return RR_type::CNAME; }

  bool operator==(RR_CNAME const& rhs) const { return str() == rhs.str(); }
  bool operator<(RR_CNAME const& rhs) const { return str() < rhs.str(); }

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

  std::optional<std::string> as_str() const { return str(); }

  std::string const&       str() const { return ptrdname_; }
  char const*              c_str() const { return str().c_str(); }
  constexpr static RR_type rr_type() { return RR_type::PTR; }

  bool operator==(RR_PTR const& rhs) const { return str() == rhs.str(); }
  bool operator<(RR_PTR const& rhs) const { return str() < rhs.str(); }

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

  std::optional<std::string> as_str() const { return exchange(); }

  std::string const& exchange() const { return exchange_; }
  uint16_t           preference() const { return preference_; }

  constexpr static RR_type rr_type() { return RR_type::MX; }

  bool operator==(RR_MX const& rhs) const
  {
    return (preference() == rhs.preference()) && (exchange() == rhs.exchange());
  }
  bool operator<(RR_MX const& rhs) const
  {
    if (preference() == rhs.preference())
      return exchange() < rhs.exchange();
    return preference() < rhs.preference();
  }

private:
  std::string exchange_;
  uint16_t    preference_;
};

class RR_TXT {
public:
  explicit RR_TXT(std::string txt_data)
    : txt_data_(txt_data)
  {
  }

  std::optional<std::string> as_str() const { return str(); }

  char const*        c_str() const { return str().c_str(); }
  std::string const& str() const { return txt_data_; }
  constexpr static RR_type rr_type() { return RR_type::TXT; }

  bool operator==(RR_TXT const& rhs) const { return str() == rhs.str(); }
  bool operator<(RR_TXT const& rhs) const { return str() < rhs.str(); }

private:
  std::string txt_data_;
};

class RR_AAAA {
public:
  RR_AAAA(uint8_t const* rd, size_t sz);

  std::optional<std::string> as_str() const { return std::string{c_str()}; }

  sockaddr_in6 const& addr() const { return addr_; }
  char const*         c_str() const { return str_; }
  constexpr static RR_type rr_type() { return RR_type::AAAA; }

  bool operator==(RR_AAAA const& rhs) const
  {
    return strcmp(c_str(), rhs.c_str()) == 0;
  }
  bool operator<(RR_AAAA const& rhs) const
  {
    return strcmp(c_str(), rhs.c_str()) < 0;
  }

private:
  sockaddr_in6 addr_;
  char         str_[INET6_ADDRSTRLEN];
};

class RR_TLSA {
public:
  using octet       = unsigned char;
  using container_t = iobuffer<octet>;

  RR_TLSA(uint8_t                cert_usage,
          uint8_t                selector,
          uint8_t                matching_type,
          std::span<octet const> data);
  unsigned cert_usage() const { return cert_usage_; }
  unsigned selector() const { return selector_; }
  unsigned matching_type() const { return matching_type_; }

  // container_t const& assoc_data() const { return assoc_data_; }

  // doesn't have a string representation
  std::optional<std::string> as_str() const { return {}; }

  constexpr static RR_type rr_type() { return RR_type::TLSA; }

  std::span<octet const> assoc_data() const
  {
    return {assoc_data_.data(), assoc_data_.size()};
  }

  bool operator==(RR_TLSA const& rhs) const
  {
    return (cert_usage() == rhs.cert_usage()) &&
           (selector() == rhs.selector()) &&
           (matching_type() == rhs.matching_type()) &&
           (assoc_data_ == rhs.assoc_data_);
  }
  bool operator<(RR_TLSA const& rhs) const
  {
    if (!(*this == rhs))
      return assoc_data_ < rhs.assoc_data_;
    return false;
  }

private:
  container_t assoc_data_;
  uint8_t     cert_usage_;
  uint8_t     selector_;
  uint8_t     matching_type_;
};

using RR =
    std::variant<RR_A, RR_CNAME, RR_PTR, RR_MX, RR_TXT, RR_AAAA, RR_TLSA>;

using RR_collection = std::vector<RR>;

} // namespace DNS

#endif // DNS_RRS_DOT_HPP

#include "DNS-priv.hpp"

#include "IP4.hpp"
#include "IP6.hpp"
#include "Sock.hpp"

#include <glog/logging.h>

#include <limits>
#include <memory>
#include <tuple>

#include <experimental/random>

#include <glog/logging.h>

#include <arpa/nameser.h>

#include "osutil.hpp"

auto constexpr max_udp_sz{uint16_t(4 * 1024)};

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
  return N;
}

struct nameserver {
  char const* host;             // name used to match cert
  char const* addr;
  char const* port;
};

constexpr nameserver nameservers[]{
    {
        "localhost",
        "127.0.0.1",
        "domain",
    },
    {
        "localhost",
        "::1",
        "domain",
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.1.1.1",
        "domain-s",
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.0.0.1",
        "domain-s",
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1111",
        "domain-s",
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1001",
        "domain-s",
    },
    {
        "dns.quad9.net",
        "9.9.9.10",
        "domain-s",
    },
    {
        "dns.quad9.net",
        "149.112.112.10",
        "domain-s",
    },
    {
        "dns.quad9.net",
        "2620:fe::10",
        "domain-s",
    },
};

/*
                                           1  1  1  1  1  1
             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      ID                       |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    QDCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ANCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    NSCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ARCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 */

using octet = unsigned char;

octet constexpr lo(uint16_t n) { return octet(n & 0xFF); }
octet constexpr hi(uint16_t n) { return octet((n >> 8) & 0xFF); }

class header {
  octet id_hi_;
  octet id_lo_;

  octet flags_0_{1}; // recursion desired
  octet flags_1_{0};

  octet qdcount_hi_{0};
  octet qdcount_lo_{1}; // 1 question

  octet ancount_hi_{0};
  octet ancount_lo_{0};

  octet nscount_hi_{0};
  octet nscount_lo_{0};

  octet arcount_hi_{0};
  octet arcount_lo_{1}; // 1 additional for the OPT

public:
  explicit header(uint16_t id)
    : id_hi_(hi(id))
    , id_lo_(lo(id))
  {
  }

  uint16_t id() const { return (id_hi_ << 8) + id_lo_; }

  uint16_t qdcount() const { return (qdcount_hi_ << 8) + qdcount_lo_; }
  uint16_t ancount() const { return (ancount_hi_ << 8) + ancount_lo_; }
  uint16_t nscount() const { return (nscount_hi_ << 8) + nscount_lo_; }
  uint16_t arcount() const { return (arcount_hi_ << 8) + arcount_lo_; }

  bool checking_disabled() const { return (flags_1_ & 0x10) != 0; }
  bool authentic_data() const { return (flags_1_ & 0x20) != 0; }
  bool recursion_available() const { return (flags_1_ & 0x80) != 0; }

  uint16_t rcode() const { return flags_1_ & 0xf; }
};

class question {
  octet qtype_hi_;
  octet qtype_lo_;

  octet qclass_hi_;
  octet qclass_lo_;

public:
  explicit question(DNS::RR_type qtype, uint16_t qclass)
    : qtype_hi_(hi(static_cast<uint16_t>(qtype)))
    , qtype_lo_(lo(static_cast<uint16_t>(qtype)))
    , qclass_hi_(hi(qclass))
    , qclass_lo_(lo(qclass))
  {
  }

  uint16_t qtype() const { return (qtype_hi_ << 8) + qtype_lo_; }
  uint16_t qclass() const { return (qclass_hi_ << 8) + qclass_lo_; }
};

/*

<https://tools.ietf.org/html/rfc6891#section-6.1.2>

       +------------+--------------+------------------------------+
       | Field Name | Field Type   | Description                  |
       +------------+--------------+------------------------------+
       | NAME       | domain name  | MUST be 0 (root domain)      |
       | TYPE       | u_int16_t    | OPT (41)                     |
       | CLASS      | u_int16_t    | requestor's UDP payload size |
       | TTL        | u_int32_t    | extended RCODE and flags     |
       | RDLEN      | u_int16_t    | length of all RDATA          |
       | RDATA      | octet stream | {attribute,value} pairs      |
       +------------+--------------+------------------------------+

<https://tools.ietf.org/html/rfc3225>

3. Protocol Changes, in place of TTL

                +0 (MSB)                +1 (LSB)
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      0: |   EXTENDED-RCODE      |       VERSION         |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      2: |DO|                    Z                       |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/

class edns0_opt_meta_rr {
  octet root_domain_name_{0}; // must be zero

  octet type_hi_{0};
  octet type_lo_{ns_t_opt};

  octet class_hi_; // UDP payload size
  octet class_lo_;

  octet extended_rcode_{0};
  octet version_{0};

  octet z_hi_{0x80}; // "DNSSEC OK" (DO) bit
  octet z_lo_{0};

  octet rdlen_hi_{0};
  octet rdlen_lo_{0};

public:
  explicit edns0_opt_meta_rr(uint16_t max_udp_sz)
    : class_hi_(hi(max_udp_sz))
    , class_lo_(lo(max_udp_sz))
  {
  }

  uint16_t extended_rcode() const { return extended_rcode_; }
};

/*

<https://tools.ietf.org/html/rfc1035>

4.1.3. Resource record format
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 */

class rr {
  octet type_hi_;
  octet type_lo_;

  octet class_hi_;
  octet class_lo_;

  octet ttl_0_;
  octet ttl_1_;
  octet ttl_2_;
  octet ttl_3_;

  octet rdlength_hi_;
  octet rdlength_lo_;

public:
  uint16_t rr_type() const { return (uint16_t(type_hi_) << 8) + type_lo_; }
  uint16_t rr_class() const { return (uint16_t(type_hi_) << 8) + type_lo_; }
  uint32_t rr_ttl() const
  {
    return (uint32_t(ttl_0_) << 24) + (uint32_t(ttl_1_) << 16)
           + (uint32_t(ttl_2_) << 8) + (uint32_t(ttl_3_));
  }

  uint16_t rdlength() const { return (rdlength_hi_ << 8) + rdlength_lo_; }

  unsigned char const* rddata() const
  {
    return reinterpret_cast<unsigned char const*>(this) + sizeof(rr);
  }

  char const* cdata() const
  {
    return reinterpret_cast<char const*>(this) + sizeof(rr);
  }

  unsigned char const* next_rr_name() const { return rddata() + rdlength(); }
};

auto uztosl(size_t uznum)
{
  CHECK_LE(uznum, size_t(std::numeric_limits<long>::max()));
  return static_cast<long>(uznum);
}

auto constexpr max_indirs = 50; // maximum indirections allowed for a name

// return the length of the expansion of an encoded domain name, or -1
// if the encoding is invalid

int name_length(unsigned char const* encoded, unsigned char const* buf, int len)
{
  int n = 0;
  int indir = 0; // count indirections

  // Allow the caller to pass us buf + len and have us check for it.
  if (encoded >= buf + len)
    return -1;

  while (*encoded) {

    auto top = (*encoded & NS_CMPRSFLGS);

    if (top == NS_CMPRSFLGS) {
      // Check the offset and go there.
      if (encoded + 1 >= buf + len)
        return -1;

      auto offset = (*encoded & ~NS_CMPRSFLGS) << 8 | *(encoded + 1);
      if (offset >= len)
        return -1;

      encoded = buf + offset;

      // If we've seen more indirects than the message length,
      // then there's a loop.
      ++indir;
      if (indir > len || indir > max_indirs)
        return -1;
    }
    else if (top == 0) {
      auto offset = *encoded;
      if (encoded + offset + 1 >= buf + len)
        return -1;

      ++encoded;

      while (offset--) {
        n += (*encoded == '.' || *encoded == '\\') ? 2 : 1;
        encoded++;
      }

      ++n;
    }
    else {
      // RFC 1035 4.1.4 says other options (01, 10) for top 2
      // bits are reserved.
      return -1;
    }
  }

  // If there were any labels at all, then the number of dots is one
  // less than the number of labels, so subtract one.

  return n ? n - 1 : n;
}

bool expand_name(unsigned char const* encoded,
                 unsigned char const* buf,
                 int len,
                 std::string& s,
                 int* enclen)
{
  s.clear();

  int indir = 0;

  auto nlen = name_length(encoded, buf, len);
  if (nlen < 0) {
    LOG(WARNING) << "bad name";
    return false;
  }

  s.reserve(nlen + 1);

  if (nlen == 0) {
    // RFC2181 says this should be ".": the root of the DNS tree.
    // Since this function strips trailing dots though, it becomes ""s

    // indirect root label (like 0xc0 0x0c) is 2 bytes long
    if ((*encoded & NS_CMPRSFLGS) == NS_CMPRSFLGS)
      *enclen = 2;
    else
      *enclen = 1; // the caller should move one byte to get past this

    return true;
  }

  // error-checking done by name_length()
  auto p = encoded;
  while (*p) {
    if ((*p & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
      if (!indir) {
        *enclen = uztosl(p + 2U - encoded);
        indir = 1;
      }
      p = buf + ((*p & ~NS_CMPRSFLGS) << 8 | *(p + 1));
    }
    else {
      int len = *p;
      p++;
      while (len--) {
        if (*p == '.' || *p == '\\')
          s += '\\';
        s += static_cast<char>(*p);
        p++;
      }
      s += '.';
    }
  }
  if (!indir)
    *enclen = uztosl(p + 1U - encoded);

  if (s.length() && ('.' == s.back())) {
    s.pop_back();
  }

  return true;
}

// return the length of the encoded name

int name_put(unsigned char* bfr, char const* name)
{
  auto q = bfr;

  if ((name[0] == '.') && (name[1] == '\0'))
    name++;

  while (*name) {
    if (*name == '.') {
      LOG(WARNING) << "zero length label";
      return -1;
    }

    uint8_t len = 0;
    char const* p;

    for (p = name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      len++;
    }
    if (len > 63) {
      LOG(WARNING) << "label exceeds 63 octets";
      return -1;
    }

    *q++ = len;
    for (p = name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      *q++ = *p;
    }

    if (!*p)
      break;

    name = p + 1;
  }

  // Add the zero-length label at the end.
  *q++ = 0;

  auto const sz = q - bfr;
  if (sz > 255) {
    LOG(WARNING) << "domain name exceeds 255 octets";
    return -1;
  }

  return sz;
}

// returns a unique_ptr to an array of chars and it's size in q_bfr_sz

DNS::pkt
create_question(char const* name, DNS::RR_type type, uint16_t cls, uint16_t id)
{
  // size to allocate may be larger than needed if backslash escapes
  // are used in domain name

  auto const sz_alloc = strlen(name) + 2 + sizeof(header) + sizeof(question)
                        + sizeof(edns0_opt_meta_rr);

  auto bfr = std::make_unique<unsigned char[]>(sz_alloc);

  auto q = bfr.get();

  new (q) header(id);
  q += sizeof(header);

  auto len = name_put(q, name);
  CHECK_GE(len, 1) << "malformed domain name " << name;
  q += len;

  new (q) question(type, cls);
  q += sizeof(question);

  new (q) edns0_opt_meta_rr(max_udp_sz);
  q += sizeof(edns0_opt_meta_rr);

  // verify constructed size is less than or equal to allocated size
  auto sz = q - bfr.get();
  CHECK_LE(sz, sz_alloc);

  return DNS::pkt{std::move(bfr), static_cast<uint16_t>(sz)};
}

namespace DNS {

Resolver::Resolver()
{
  ns_sock_ = [&] {
    auto tries = countof(nameservers);
    auto ns = std::experimental::randint(
        0, static_cast<int>(countof(nameservers) - 1));

    while (tries--) {

      // try the next one, with wrap
      if (++ns == countof(nameservers)) {
        ns = 0;
      }
      auto const& nameserver = nameservers[ns];

      int fd = -1;
      uint16_t port = osutil::get_port(nameserver.port);

      if (IP4::is_address(nameserver.addr)) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        PCHECK(fd >= 0) << "socket() failed";

        auto in4{sockaddr_in{}};
        in4.sin_family = AF_INET;
        in4.sin_port = htons(port);
        CHECK_EQ(inet_pton(AF_INET, nameserver.addr,
                           reinterpret_cast<void*>(&in4.sin_addr)),
                 1);
        if (connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4))) {
          PLOG(INFO) << "connect failed " << nameserver.host << '['
                     << nameserver.addr << "]:" << nameserver.port;
          close(fd);
          continue;
        }
      }
      else if (IP6::is_address(nameserver.addr)) {
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        PCHECK(fd >= 0) << "socket() failed";

        auto in6{sockaddr_in6{}};
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        CHECK_EQ(inet_pton(AF_INET6, nameserver.addr,
                           reinterpret_cast<void*>(&in6.sin6_addr)),
                 1);
        if (connect(fd, reinterpret_cast<const sockaddr*>(&in6), sizeof(in6))) {
          PLOG(INFO) << "connect failed " << nameserver.host << '['
                     << nameserver.addr << "]:" << nameserver.port;
          close(fd);
          continue;
        }
      }

      auto sock = std::make_unique<Sock>(fd, fd);

      if (port != 53) {
        DNS::RR_set tlsa_rrs; // empty
        sock->starttls_client(nullptr, nameserver.host, tlsa_rrs, false);
        if (sock->verified()) {
          LOG(INFO) << "using TLS " << nameserver.host << '[' << nameserver.addr
                    << "]:" << nameserver.port;
          return sock;
        }
        close(fd);
        continue;
      }

      LOG(INFO) << "using " << nameserver.host << '[' << nameserver.addr
                << "]:" << nameserver.port;
      return sock;
    }

    LOG(FATAL) << "no nameservers left to try";
  }();
}

void Resolver::send(pkt const& q)
{
  uint16_t sz = htons(q.sz);

  ns_sock_->out().write(reinterpret_cast<char const*>(&sz), sizeof sz);
  ns_sock_->out().write(reinterpret_cast<char const*>(q.bfr.get()), q.sz);
  ns_sock_->out().flush();
}

void Resolver::receive(pkt& a)
{
  uint16_t sz = 0;

  ns_sock_->in().read(reinterpret_cast<char*>(&sz), sizeof sz);
  a.sz = ntohs(sz);

  a.bfr = std::make_unique<unsigned char[]>(a.sz);
  ns_sock_->in().read(reinterpret_cast<char*>(a.bfr.get()), a.sz);

  if (!ns_sock_->in()) {
    LOG(WARNING) << "Resolver::receive read only " << ns_sock_->in().gcount()
                 << " octets";
  }
}

RR_set Resolver::get_records(RR_type typ, char const* name)
{
  Query q(*this, typ, name);
  return q.get_records();
}

std::vector<std::string> Resolver::get_strings(RR_type typ, char const* name)
{
  Query q(*this, typ, name);
  return q.get_strings();
}

Query::Query(Resolver& res, RR_type type, char const* name)
{
  static_assert(sizeof(header) == 12);
  static_assert(sizeof(question) == 4);
  static_assert(sizeof(edns0_opt_meta_rr) == 11);
  static_assert(sizeof(rr) == 10);

  auto id = std::experimental::randint(uint16_t(0),
                                       std::numeric_limits<uint16_t>::max());
  uint16_t cls = ns_c_in;
  q_ = create_question(name, type, cls, id);

  res.send(q_);
  res.receive(a_);

  auto p = static_cast<unsigned char const*>(a_.bfr.get());
  auto pend = p + a_.sz;

  if ((p + sizeof(header)) >= pend) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }
  auto hdr_p = reinterpret_cast<header const*>(p);
  p += sizeof(header);

  if (hdr_p->id() != id) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "packet out of order; ids don't match";
    return;
  }

  rcode_ = hdr_p->rcode();
  switch (rcode_) {
  case ns_r_noerror:
    break;

  case ns_r_nxdomain:
    nx_domain_ = true;
    break;

  default:
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "name lookup error: " << rcode_c_str(rcode_) << " for "
                 << name << "/" << type;
  }

  authentic_data_ = hdr_p->authentic_data();
  has_record_ = hdr_p->ancount() != 0;

  // check the question part of the replay

  if (hdr_p->qdcount() != 1) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "question not copied into answer";
    return;
  }

  std::string qname;
  auto enc_len = 0;

  if (!expand_name(p, a_.bfr.get(), a_.sz, qname, &enc_len)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }
  p += enc_len;
  if (p >= pend) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }

  if (!iequal(qname, name)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "names don't match, " << qname << " != " << name;
    return;
  }

  if ((p + sizeof(question)) >= pend) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }
  auto question_p = reinterpret_cast<question const*>(p);

  if (question_p->qtype() != static_cast<uint16_t>(type)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "qtypes don't match, " << question_p->qtype()
                 << " != " << type;
    return;
  }
  if (question_p->qclass() != cls) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "qclasses don't match, " << question_p->qclass()
                 << " != " << cls;
    return;
  }

  p += sizeof(question);
  if (p >= pend) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }

  // skip answers
  for (auto i = 0; i < hdr_p->ancount(); ++i) {
    std::string name;
    auto enc_len = 0;
    if (!expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    p += enc_len;
    if ((p + sizeof(rr)) > pend) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    auto rr_p = reinterpret_cast<rr const*>(p);
    p = rr_p->next_rr_name();
  }

  // skip nameservers
  for (auto i = 0; i < hdr_p->nscount(); ++i) {
    std::string name;
    auto enc_len = 0;
    if (!expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    p += enc_len;
    if ((p + sizeof(rr)) > pend) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    auto rr_p = reinterpret_cast<rr const*>(p);
    p = rr_p->next_rr_name();
  }

  // check additional for OPT record
  for (auto i = 0; i < hdr_p->arcount(); ++i) {
    std::string name;
    auto enc_len = 0;
    if (!expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    p += enc_len;
    if ((p + sizeof(rr)) > pend) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return;
    }
    auto rr_p = reinterpret_cast<rr const*>(p);

    if (rr_p->rr_type() == ns_t_opt) {
      auto opt_p = reinterpret_cast<edns0_opt_meta_rr const*>(p);
      extended_rcode_ = (opt_p->extended_rcode() << 4) + hdr_p->rcode();
    }
    else {
      LOG(INFO) << "unknown additional record, name == " << name;
      LOG(INFO) << "rr_p->type()  == " << DNS::RR_type_c_str(rr_p->rr_type());
      LOG(INFO) << "rr_p->class() == " << rr_p->rr_class();
      LOG(INFO) << "rr_p->ttl()   == " << rr_p->rr_ttl();
    }

    p = rr_p->next_rr_name();
  }

  auto size_check = p - static_cast<unsigned char const*>(a_.bfr.get());
  if (size_check != a_.sz) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet size";
    return;
  }
}

RR_set Query::get_records()
{
  RR_set ret;

  if (bogus_or_indeterminate_) // if ctor() found and error with the packet
    return ret;

  auto p = static_cast<unsigned char const*>(a_.bfr.get());
  auto pend = p + a_.sz;

  auto hdr_p = reinterpret_cast<header const*>(p);
  p += sizeof(header);

  // skip queries
  for (auto i = 0; i < hdr_p->qdcount(); ++i) {
    std::string qname;
    auto enc_len = 0;

    CHECK(expand_name(p, a_.bfr.get(), a_.sz, qname, &enc_len));
    p += enc_len;
    // auto question_p = reinterpret_cast<question const*>(p);
    p += sizeof(question);
  }

  // get answers
  for (auto i = 0; i < hdr_p->ancount(); ++i) {
    std::string name;
    auto enc_len = 0;

    CHECK(expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len));
    p += enc_len;
    if ((p + sizeof(rr)) > pend) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return RR_set{};
    }
    auto rr_p = reinterpret_cast<rr const*>(p);
    if ((p + rr_p->rdlength()) > pend) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return RR_set{};
    }

    auto typ = static_cast<DNS::RR_type>(rr_p->rr_type());
    switch (typ) {
    case DNS::RR_type::A: {
      if (rr_p->rdlength() != 4) {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus A";
        return RR_set{};
      }
      ret.emplace_back(RR_A{rr_p->rddata(), rr_p->rdlength()});
      break;
    }

    case DNS::RR_type::CNAME: {
      p = rr_p->rddata();
      if (expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
        ret.emplace_back(RR_CNAME{name});
      }
      else {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus CNAME";
        return RR_set{};
      }
      break;
    }

    case DNS::RR_type::PTR: {
      p = rr_p->rddata();
      if (expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
        ret.emplace_back(RR_PTR{name});
      }
      else {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus PTR";
        return RR_set{};
      }
      break;
    }

    case DNS::RR_type::MX: {
      if (rr_p->rdlength() < 3) {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus MX";
        return RR_set{};
      }
      p = rr_p->rddata();
      uint16_t preference = (p[0] << 8) + p[1];
      p += 2;
      if (expand_name(p, a_.bfr.get(), a_.sz, name, &enc_len)) {
        ret.emplace_back(RR_MX{name, preference});
      }
      else {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus MX";
        return RR_set{};
      }
      break;
    }

    case DNS::RR_type::TXT: {
      if (rr_p->rdlength() < 1) {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus TXT";
        return RR_set{};
      }
      std::string str;
      p = rr_p->rddata();
      do {
        if ((p + 1 + *p) > rr_p->next_rr_name()) {
          bogus_or_indeterminate_ = true;
          LOG(WARNING) << "bogus string in TXT record";
          return RR_set{};
        }
        str += std::string(reinterpret_cast<char const*>(p) + 1, *p);
        p = p + *p + 1;
      } while (p < rr_p->next_rr_name());
      ret.emplace_back(RR_TXT{str});
      break;
    }

    case DNS::RR_type::AAAA: {
      if (rr_p->rdlength() != 16) {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus AAAA";
        return RR_set{};
      }
      ret.emplace_back(RR_AAAA{rr_p->rddata(), rr_p->rdlength()});
      break;
    }

    case DNS::RR_type::RRSIG: {
      // LOG(WARNING) << "#### FIXME! RRSIG";
      // ret.emplace_back(RR_RRSIG{rr_p->rddata(), rr_p->rdlength()});
      break;
    }

    case DNS::RR_type::TLSA: {
      p = rr_p->rddata();

      if ((rr_p->rdlength() < 4) || (p + rr_p->rdlength()) > pend) {
        bogus_or_indeterminate_ = true;
        LOG(WARNING) << "bogus TLSA";
        return RR_set{};
      }

      uint8_t cert_usage = *p++;
      uint8_t selector = *p++;
      uint8_t matching_type = *p++;

      uint8_t const* assoc_data = p;
      size_t assoc_data_sz = rr_p->rdlength() - 3;

      ret.emplace_back(RR_TLSA{cert_usage, selector, matching_type, assoc_data,
                               assoc_data_sz});
      break;
    }

    default:
      LOG(WARNING) << "no code to process record type " << typ;
      break;
    }

    p = rr_p->next_rr_name();
  }

  return ret;
}

std::vector<std::string> Query::get_strings()
{
  std::vector<std::string> ret;

  auto rr_set = get_records();
  for (auto rr : rr_set) {
    if (std::holds_alternative<DNS::RR_A>(rr)) {
      ret.push_back(std::get<DNS::RR_A>(rr).c_str());
    }
    else if (std::holds_alternative<DNS::RR_CNAME>(rr)) {
      ret.push_back(std::get<DNS::RR_CNAME>(rr).str());
    }
    else if (std::holds_alternative<DNS::RR_PTR>(rr)) {
      ret.push_back(std::get<DNS::RR_PTR>(rr).str());
    }
    else if (std::holds_alternative<DNS::RR_AAAA>(rr)) {
      ret.push_back(std::get<DNS::RR_AAAA>(rr).c_str());
    }
    else if (std::holds_alternative<DNS::RR_MX>(rr)) {
      ret.push_back(std::get<DNS::RR_MX>(rr).exchange());
    }
  }

  return ret;
}

} // namespace DNS

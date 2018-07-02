#include "DNS-priv.hpp"

#include "DNS-iostream.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "Sock.hpp"

#include <glog/logging.h>

#include <atomic>
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

enum class sock_type : bool { stream, dgram };

struct nameserver {
  char const* host; // name used to match cert
  char const* addr;
  char const* port;
  sock_type typ;
};

constexpr nameserver nameservers[]{
    {
        "localhost",
        "127.0.0.1",
        "domain",
        sock_type::dgram,
    },
    /*
    {
        "localhost",
        "::1",
        "domain",
        sock_type::dgram,
    },
    {
        "digilicious.com",
        "127.0.0.1",
        "domain-s",
        sock_type::stream,
    },
    {
        "digilicious.com",
        "::1",
        "domain-s",
        sock_type::stream,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.1.1.1",
        "domain",
        sock_type::dgram,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.0.0.1",
        "domain-s",
        sock_type::stream,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1111",
        "domain-s",
        sock_type::stream,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1001",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns.quad9.net",
        "9.9.9.10",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns.quad9.net",
        "149.112.112.10",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns.quad9.net",
        "2620:fe::10",
        "domain-s",
        sock_type::stream,
    },
    */
};

using octet = unsigned char;

octet constexpr lo(uint16_t n) { return octet(n & 0xFF); }
octet constexpr hi(uint16_t n) { return octet((n >> 8) & 0xFF); }

uint16_t constexpr as_u16(octet hi, octet lo)
{
  return (uint16_t(hi) << 8) + lo;
}

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
    static_assert(sizeof(header) == 12);
  }

  uint16_t id() const { return as_u16(id_hi_, id_lo_); }

  uint16_t qdcount() const { return as_u16(qdcount_hi_, qdcount_lo_); }
  uint16_t ancount() const { return as_u16(ancount_hi_, ancount_lo_); }
  uint16_t nscount() const { return as_u16(nscount_hi_, nscount_lo_); }
  uint16_t arcount() const { return as_u16(arcount_hi_, arcount_lo_); }

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
    static_assert(sizeof(question) == 4);
  }

  DNS::RR_type qtype() const
  {
    auto typ = as_u16(qtype_hi_, qtype_lo_);
    return static_cast<DNS::RR_type>(typ);
  }
  uint16_t qclass() const { return as_u16(qclass_hi_, qclass_lo_); }
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
    static_assert(sizeof(edns0_opt_meta_rr) == 11);
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
  rr() { static_assert(sizeof(rr) == 10); }

  uint16_t rr_type() const { return as_u16(type_hi_, type_lo_); }
  uint16_t rr_class() const { return as_u16(class_hi_, class_lo_); }
  uint32_t rr_ttl() const
  {
    return (uint32_t(ttl_0_) << 24) + (uint32_t(ttl_1_) << 16)
           + (uint32_t(ttl_2_) << 8) + (uint32_t(ttl_3_));
  }

  uint16_t rdlength() const { return as_u16(rdlength_hi_, rdlength_lo_); }

  auto cdata() const
  {
    return reinterpret_cast<char const*>(this) + sizeof(rr);
  }
  auto rddata() const
  {
    return reinterpret_cast<unsigned char const*>(cdata());
  }
  auto next_rr_name() const { return rddata() + rdlength(); }
};

// name processing code mostly adapted from c-ares

auto uztosl(size_t uznum)
{
  CHECK_LE(uznum, size_t(std::numeric_limits<long>::max()));
  return static_cast<long>(uznum);
}

// return the length of the expansion of an encoded domain name, or -1
// if the encoding is invalid

int name_length(unsigned char const* encoded, DNS::packet const& pkt)
{
  auto constexpr max_indirs = 50; // maximum indirections allowed for a name

  int length = 0;
  int nindir = 0; // count indirections

  // Allow the caller to pass us buf + len and have us check for it.
  if (encoded >= end(pkt))
    return -1;

  while (*encoded) {

    auto top = (*encoded & NS_CMPRSFLGS);

    if (top == NS_CMPRSFLGS) {
      // Check the offset and go there.
      if (encoded + 1 >= end(pkt))
        return -1;

      auto offset = (*encoded & ~NS_CMPRSFLGS) << 8 | *(encoded + 1);
      if (offset >= size(pkt))
        return -1;

      encoded = begin(pkt) + offset;

      // If we've seen more indirects than the message length,
      // then there's a loop.
      ++nindir;
      if (nindir > size(pkt) || nindir > max_indirs)
        return -1;
    }
    else if (top == 0) {
      auto offset = *encoded;
      if (encoded + offset + 1 >= end(pkt))
        return -1;

      ++encoded;

      while (offset--) {
        length += (*encoded == '.' || *encoded == '\\') ? 2 : 1;
        encoded++;
      }

      ++length;
    }
    else {
      // RFC 1035 4.1.4 says other options (01, 10) for top 2
      // bits are reserved.
      return -1;
    }
  }

  // If there were any labels at all, then the number of dots is one
  // less than the number of labels, so subtract one.

  return length ? length - 1 : length;
}

bool expand_name(unsigned char const* encoded,
                 DNS::packet const& pkt,
                 std::string& name,
                 int& enc_len)
{
  name.clear();

  bool indir = false;

  auto nlen = name_length(encoded, pkt);
  if (nlen < 0) {
    LOG(WARNING) << "bad name";
    return false;
  }

  name.reserve(nlen + 1);

  if (nlen == 0) {
    // RFC2181 says this should be ".": the root of the DNS tree.
    // Since this function strips trailing dots though, it becomes ""s

    // indirect root label (like 0xc0 0x0c) is 2 bytes long
    if ((*encoded & NS_CMPRSFLGS) == NS_CMPRSFLGS)
      enc_len = 2;
    else
      enc_len = 1; // the caller should move one byte to get past this

    return true;
  }

  // error-checking done by name_length()
  auto p = encoded;
  while (*p) {
    if ((*p & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
      if (!indir) {
        enc_len = uztosl(p + 2 - encoded);
        indir = true;
      }
      p = begin(pkt) + ((*p & ~NS_CMPRSFLGS) << 8 | *(p + 1));
    }
    else {
      int len = *p;
      p++;
      while (len--) {
        if (*p == '.' || *p == '\\')
          name += '\\';
        name += static_cast<char>(*p);
        p++;
      }
      name += '.';
    }
  }

  if (!indir)
    enc_len = uztosl(p + 1 - encoded);

  if (name.length() && ('.' == name.back())) {
    name.pop_back();
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

DNS::packet
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

  return DNS::packet{std::move(bfr), static_cast<uint16_t>(sz)};
}

namespace DNS {

Resolver::Resolver()
{
  auto tries = countof(nameservers);

  ns_ = std::experimental::randint(0,
                                   static_cast<int>(countof(nameservers) - 1));

  while (tries--) {

    // try the next one, with wrap
    if (++ns_ == countof(nameservers))
      ns_ = 0;

    auto const& nameserver = nameservers[ns_];

    ns_fd_ = -1;
    uint16_t port = osutil::get_port(nameserver.port);

    auto typ = (nameserver.typ == sock_type::stream) ? SOCK_STREAM : SOCK_DGRAM;

    if (IP4::is_address(nameserver.addr)) {
      ns_fd_ = socket(AF_INET, typ, 0);
      PCHECK(ns_fd_ >= 0) << "socket() failed";

      auto in4{sockaddr_in{}};
      in4.sin_family = AF_INET;
      in4.sin_port = htons(port);
      CHECK_EQ(inet_pton(AF_INET, nameserver.addr,
                         reinterpret_cast<void*>(&in4.sin_addr)),
               1);
      if (connect(ns_fd_, reinterpret_cast<const sockaddr*>(&in4),
                  sizeof(in4))) {
        PLOG(INFO) << "connect failed " << nameserver.host << '['
                   << nameserver.addr << "]:" << nameserver.port;
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
    }
    else if (IP6::is_address(nameserver.addr)) {
      ns_fd_ = socket(AF_INET6, typ, 0);
      PCHECK(ns_fd_ >= 0) << "socket() failed";

      auto in6{sockaddr_in6{}};
      in6.sin6_family = AF_INET6;
      in6.sin6_port = htons(port);
      CHECK_EQ(inet_pton(AF_INET6, nameserver.addr,
                         reinterpret_cast<void*>(&in6.sin6_addr)),
               1);
      if (connect(ns_fd_, reinterpret_cast<const sockaddr*>(&in6),
                  sizeof(in6))) {
        PLOG(INFO) << "connect failed " << nameserver.host << '['
                   << nameserver.addr << "]:" << nameserver.port;
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
    }

    POSIX::set_nonblocking(ns_fd_);

    if (nameserver.typ == sock_type::stream) {
      ns_sock_ = std::make_unique<Sock>(ns_fd_, ns_fd_);

      if (port != 53) {
        DNS::RR_set tlsa_rrs; // empty FIXME!
        ns_sock_->starttls_client(nullptr, nameserver.host, tlsa_rrs, false);
        if (ns_sock_->verified()) {
          ns_fd_ = -1;
          return;
        }
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
      ns_fd_ = -1;
    }

    return;
  }

  LOG(FATAL) << "no nameservers left to try";
}

packet Resolver::xchg(packet const& q)
{
  if (nameservers[ns_].typ == sock_type::stream) {
    CHECK_EQ(ns_fd_, -1);

    uint16_t sz = htons(std::size(q));

    ns_sock_->out().write(reinterpret_cast<char const*>(&sz), sizeof sz);
    ns_sock_->out().write(reinterpret_cast<char const*>(begin(q)), size(q));
    ns_sock_->out().flush();

    sz = 0;

    ns_sock_->in().read(reinterpret_cast<char*>(&sz), sizeof sz);
    sz = ntohs(sz);

    auto bfr = std::make_unique<unsigned char[]>(sz);
    ns_sock_->in().read(reinterpret_cast<char*>(bfr.get()), sz);

    if (!ns_sock_->in()) {
      LOG(WARNING) << "Resolver::xchg was able to read only "
                   << ns_sock_->in().gcount() << " octets";
    }

    return packet{std::move(bfr), sz};
  }

  CHECK(nameservers[ns_].typ == sock_type::dgram);
  CHECK_GE(ns_fd_, 0);

  CHECK_EQ(send(ns_fd_, std::begin(q), std::size(q), 0), std::size(q));

  auto sz = max_udp_sz;
  auto bfr = std::make_unique<unsigned char[]>(sz);

  auto constexpr hook{[]() {}};
  auto t_o{false};
  auto a_buf = reinterpret_cast<char*>(bfr.get());
  auto a_buflen
      = POSIX::read(ns_fd_, a_buf, int(sz), hook, std::chrono::seconds(7), t_o);

  if (a_buflen < 0) {
    LOG(WARNING) << "DNS read failed";
    return packet{std::make_unique<unsigned char[]>(0), uint16_t(0)};
  }

  if (t_o) {
    LOG(WARNING) << "DNS read timed out";
    return packet{std::make_unique<unsigned char[]>(0), uint16_t(0)};
  }

  sz = a_buflen;
  return packet{std::move(bfr), sz};
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

bool Query::xchg_(Resolver& res, uint16_t id)
{
  auto tries = 3;

  while (tries) {

    a_ = res.xchg(q_);

    if (!size(a_)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "no reply from nameserver";
      return false;
    }

    if (size(a_) < sizeof(header)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "packet too small";
      return false;
    }

    auto const hdr_p = reinterpret_cast<header const*>(begin(a_));

    if (hdr_p->id() == id)
      break;

    LOG(WARNING) << "packet out of order; ids don't match, got " << hdr_p->id()
                 << " expecting " << id;
    --tries;
  }

  if (tries)
    return true;

  bogus_or_indeterminate_ = true;
  LOG(WARNING) << "no tries left, giving up";

  return false;
}

Query::Query(Resolver& res, RR_type type, char const* name)
  : type_(type)
{
  static_assert(std::numeric_limits<uint16_t>::min() == 0);
  static_assert(std::numeric_limits<uint16_t>::max() == 65535);

  uint16_t id
      = std::experimental::randint(std::numeric_limits<uint16_t>::min(),
                                   std::numeric_limits<uint16_t>::max());

  uint16_t cls = ns_c_in;
  q_ = create_question(name, type, cls, id);

  if (!xchg_(res, id))
    return;

  if (size(a_) < sizeof(header)) {
    bogus_or_indeterminate_ = true;
    LOG(INFO) << "bad (or no) reply for " << name << '/' << type;
    return;
  }

  check_answer_(res, type, name);
}

void Query::check_answer_(Resolver& res, RR_type type, char const* name)
{
  // We grab some stuff from the question we generated.  This is not
  // an un-trusted datum from afar.

  auto cls{[this, type = type]() {
    auto q = begin(q_);
    auto const q_hdr_p = reinterpret_cast<header const*>(q);
    CHECK_EQ(q_hdr_p->qdcount(), uint16_t(1));
    q += sizeof(header);
    std::string qname;
    int name_len;
    CHECK(expand_name(q, q_, qname, name_len));
    q += name_len;
    auto const question_p = reinterpret_cast<question const*>(q);
    CHECK(question_p->qtype() == type)
        << question_p->qtype() << " != " << type << '\n';
    return question_p->qclass();
  }()};

  auto const hdr_p = reinterpret_cast<header const*>(begin(a_));

  rcode_ = hdr_p->rcode();
  switch (rcode_) {
  case ns_r_noerror:
    break;

  case ns_r_nxdomain:
    nx_domain_ = true;
    break;

  case ns_r_servfail:
    bogus_or_indeterminate_ = true;
    break;

  default:
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "name lookup error: " << rcode_c_str(rcode_) << " for "
                 << name << '/' << type;
    break;
  }

  authentic_data_ = hdr_p->authentic_data();
  has_record_ = hdr_p->ancount() != 0;

  // check the question part of the replay

  if (hdr_p->qdcount() != 1) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "question not copied into answer for " << name << '/'
                 << type;
    return;
  }

  auto p = begin(a_) + sizeof(header);

  std::string qname;
  int enc_len = 0;
  if (!expand_name(p, a_, qname, enc_len)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }
  p += enc_len;
  if (p >= end(a_)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }

  if (!Domain::match(qname, name)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "names don't match, " << qname << " != " << name;
    return;
  }

  if ((p + sizeof(question)) >= end(a_)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet";
    return;
  }

  auto question_p = reinterpret_cast<question const*>(p);
  p += sizeof(question);

  if (question_p->qtype() != type) {
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

  // answers and nameservers
  for (auto i = 0; i < (hdr_p->ancount() + hdr_p->nscount()); ++i) {
    std::string x;
    auto enc_len = 0;
    if (!expand_name(p, a_, x, enc_len)
        || ((p + enc_len + sizeof(rr)) > end(a_))) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet in answer or nameserver section for " << name
                   << '/' << type;
      return;
    }
    p += enc_len;
    auto rr_p = reinterpret_cast<rr const*>(p);
    p = rr_p->next_rr_name();
  }

  // check additional section for OPT record
  for (auto i = 0; i < hdr_p->arcount(); ++i) {
    std::string x;
    auto enc_len = 0;
    if (!expand_name(p, a_, x, enc_len)
        || ((p + enc_len + sizeof(rr)) > end(a_))) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet in additional section for " << name << '/'
                   << type;
      return;
    }
    p += enc_len;
    auto rr_p = reinterpret_cast<rr const*>(p);

    switch (rr_p->rr_type()) {
    case ns_t_opt: {
      auto opt_p = reinterpret_cast<edns0_opt_meta_rr const*>(p);
      extended_rcode_ = (opt_p->extended_rcode() << 4) + hdr_p->rcode();
      break;
    }

    case ns_t_a:
    case ns_t_aaaa:
    case ns_t_ns:
      // nameserver records often included with associated address info
      break;

    default:
      LOG(INFO) << "unknown additional record, name == " << name;
      LOG(INFO) << "rr_p->type()  == " << DNS::RR_type_c_str(rr_p->rr_type());
      LOG(INFO) << "rr_p->class() == " << rr_p->rr_class();
      LOG(INFO) << "rr_p->ttl()   == " << rr_p->rr_ttl();
      break;
    }

    p = rr_p->next_rr_name();
  }

  auto size_check = p - begin(a_);
  if (size_check != size(a_)) {
    bogus_or_indeterminate_ = true;
    LOG(WARNING) << "bad packet size for " << name << '/' << type;
    return;
  }
}

std::optional<RR> get_A(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  if (rr_p->rdlength() != 4) {
    LOG(WARNING) << "bogus A record";
    err = true;
    return {};
  }
  return RR_A{rr_p->rddata(), rr_p->rdlength()};
}

std::optional<RR> get_CNAME(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  std::string name;
  int enc_len;
  if (!expand_name(rr_p->rddata(), pkt, name, enc_len)) {
    LOG(WARNING) << "bogus CNAME record";
    err = true;
    return {};
  }
  return RR_CNAME{name};
}

std::optional<RR> get_PTR(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  std::string name;
  int enc_len;
  if (!expand_name(rr_p->rddata(), pkt, name, enc_len)) {
    LOG(WARNING) << "bogus PTR";
    err = true;
    return {};
  }
  return RR_PTR{name};
}

std::optional<RR> get_MX(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  std::string name;
  int enc_len;
  if (rr_p->rdlength() < 3) {
    LOG(WARNING) << "bogus MX record";
    err = true;
    return {};
  }
  auto p = rr_p->rddata();
  auto const preference = as_u16(p[0], p[1]);
  p += 2;
  if (!expand_name(p, pkt, name, enc_len)) {
    LOG(WARNING) << "bogus MX record";
    err = true;
    return {};
  }
  return RR_MX{name, preference};
}

std::optional<RR> get_TXT(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  if (rr_p->rdlength() < 1) {
    LOG(WARNING) << "bogus TXT";
    err = true;
    return {};
  }
  std::string str;
  auto p = rr_p->rddata();
  do {
    if ((p + 1 + *p) > rr_p->next_rr_name()) {
      LOG(WARNING) << "bogus string in TXT record";
      err = true;
      return {};
    }
    str += std::string(reinterpret_cast<char const*>(p) + 1, *p);
    p = p + *p + 1;
  } while (p < rr_p->next_rr_name());
  return RR_TXT{str};
}

std::optional<RR> get_AAAA(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  if (rr_p->rdlength() != 16) {
    LOG(WARNING) << "bogus AAAA";
    err = true;
    return {};
  }
  return RR_AAAA{rr_p->rddata(), rr_p->rdlength()};
}

std::optional<RR> get_RRSIG(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  // LOG(WARNING) << "#### FIXME! RRSIG";
  // return RR_RRSIG{rr_p->rddata(), rr_p->rdlength()});
  return {};
}

std::optional<RR> get_TLSA(rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  if (rr_p->rdlength() < 4) {
    LOG(WARNING) << "bogus TLSA record";
    err = true;
    return {};
  }

  auto p = rr_p->rddata();

  uint8_t cert_usage = *p++;
  uint8_t selector = *p++;
  uint8_t matching_type = *p++;

  uint8_t const* assoc_data = p;
  size_t assoc_data_sz = rr_p->rdlength() - 3;

  return RR_TLSA{cert_usage, selector, matching_type, assoc_data,
                 assoc_data_sz};
}

std::optional<RR>
get_rr(DNS::RR_type typ, rr const* rr_p, DNS::packet const& pkt, bool& err)
{
  switch (typ) {
  case DNS::RR_type::A:
    return get_A(rr_p, pkt, err);

  case DNS::RR_type::CNAME:
    return get_CNAME(rr_p, pkt, err);

  case DNS::RR_type::PTR:
    return get_PTR(rr_p, pkt, err);

  case DNS::RR_type::MX:
    return get_MX(rr_p, pkt, err);

  case DNS::RR_type::TXT:
    return get_TXT(rr_p, pkt, err);

  case DNS::RR_type::AAAA:
    return get_AAAA(rr_p, pkt, err);

  case DNS::RR_type::RRSIG:
    return get_RRSIG(rr_p, pkt, err);

  case DNS::RR_type::TLSA:
    return get_TLSA(rr_p, pkt, err);

  default:
    break;
  }

  LOG(WARNING) << "unknown RR type " << typ;
  return {};
}

RR_set Query::get_records()
{
  RR_set ret;

  if (bogus_or_indeterminate_) // if ctor() found and error with the packet
    return ret;

  auto const hdr_p = reinterpret_cast<header const*>(begin(a_));

  auto p = begin(a_) + sizeof(header);

  // skip queries
  for (auto i = 0; i < hdr_p->qdcount(); ++i) {
    std::string qname;
    auto enc_len = 0;

    CHECK(expand_name(p, a_, qname, enc_len));
    p += enc_len;
    // auto question_p = reinterpret_cast<question const*>(p);
    p += sizeof(question);
  }

  // get answers
  for (auto i = 0; i < hdr_p->ancount(); ++i) {
    std::string name;
    auto enc_len = 0;
    CHECK(expand_name(p, a_, name, enc_len));
    p += enc_len;
    if ((p + sizeof(rr)) > end(a_)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return RR_set{};
    }
    auto rr_p = reinterpret_cast<rr const*>(p);
    if ((p + rr_p->rdlength()) > end(a_)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "bad packet";
      return RR_set{};
    }

    auto typ = static_cast<DNS::RR_type>(rr_p->rr_type());

    auto rr_ret = get_rr(typ, rr_p, a_, bogus_or_indeterminate_);

    if (bogus_or_indeterminate_)
      return RR_set{};

    if (rr_ret)
      ret.emplace_back(*rr_ret);

    p = rr_p->next_rr_name();
  }

  return ret;
}

std::vector<std::string> Query::get_strings()
{
  std::vector<std::string> ret;

  auto const rr_set = get_records();

  for (auto rr : rr_set) {
    std::visit(
        [&ret, type = type_](auto const& r) {
          if (type == r.rr_type()) {
            auto s = r.as_str();
            if (s)
              ret.push_back(*s);
          }
        },
        rr);
  }

  return ret;
}

} // namespace DNS

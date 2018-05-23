#include <limits>
#include <memory>
#include <tuple>

#include <experimental/random>

#include <glog/logging.h>

#include <arpa/nameser.h>

#include "DNS-rrs.hpp"
#include "Sock.hpp"
#include "osutil.hpp"

auto constexpr max_udp_sz{uint16_t(4 * 1024)};

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
  return N;
}

struct nameserver {
  char const* host;
  char const* addr;
  char const* port;
};

constexpr nameserver nameservers[]{
    //*
      {
          "localhost",
          "127.0.0.1",
          "domain",
      },
    //*/

    /*
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.0.0.1",
        "domain-s",
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.1.1.1",
        "domain-s",
    },
    {
        "dns.quad9.net",
        "9.9.9.10",
        "domain-s",
    },
    */
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
  explicit question(DNS::RR_type qtype, uint16_t qclass = ns_c_in)
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
  octet type_lo_{41}; // OPT

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

// returns both a unique_ptr to an array of chars and it's size

auto create_question(char const* name, DNS::RR_type type, uint16_t id)
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

  new (q) question(type);
  q += sizeof(question);

  new (q) edns0_opt_meta_rr(max_udp_sz);
  q += sizeof(edns0_opt_meta_rr);

  // verify constructed size is less than or equal to allocated size
  auto sz = q - bfr.get();
  CHECK_LE(sz, sz_alloc);

  return std::make_tuple(std::move(bfr), sz);
}

bool parse_answer(unsigned char const* bfr, uint16_t sz)
{
  if (sz < sizeof(header)) {
    LOG(WARNING) << "packet too small at " << sz << " octets";
    return false;
  }

  auto p = bfr;

  auto hdr_p = reinterpret_cast<header const*>(p);
  p += sizeof(header);

  CHECK_EQ(hdr_p->id(), 0x1234);

  if (hdr_p->authentic_data()) {
    LOG(INFO) << "*** authentic data";
  }

  auto rcode = hdr_p->rcode();
  LOG(INFO) << "basic rcode == " << DNS::rcode_c_str(rcode);

  LOG(INFO) << "*** questions == " << hdr_p->qdcount();
  for (auto i = 0; i < hdr_p->qdcount(); ++i) {
    std::string qname;
    auto enc_len = 0;

    CHECK(expand_name(p, bfr, sz, qname, &enc_len));
    p += enc_len;
    auto question_p = reinterpret_cast<question const*>(p);

    LOG(INFO) << "qname == " << qname;
    LOG(INFO) << "question_p->qtype() == "
              << DNS::RR_type_c_str(question_p->qtype());
    LOG(INFO) << "question_p->qclass() == " << question_p->qclass();

    p += sizeof(question);
  }

  LOG(INFO) << "*** answers == " << hdr_p->ancount();
  for (auto i = 0; i < hdr_p->ancount(); ++i) {
    std::string name;
    auto enc_len = 0;

    CHECK(expand_name(p, bfr, sz, name, &enc_len));
    p += enc_len;
    auto rr_p = reinterpret_cast<rr const*>(p);

    LOG(INFO) << "name == " << name;
    LOG(INFO) << "rr_p->type()     == " << DNS::RR_type_c_str(rr_p->rr_type());
    LOG(INFO) << "rr_p->class()    == " << rr_p->rr_class();
    LOG(INFO) << "rr_p->ttl()      == " << rr_p->rr_ttl();
    LOG(INFO) << "rr_p->rdlength() == " << rr_p->rdlength();

    if (rr_p->rr_class() == ns_c_in) {
      auto typ = static_cast<DNS::RR_type>(rr_p->rr_type());
      switch (typ) {
      case DNS::RR_type::A:
        break;
      case DNS::RR_type::MX:
        break;
      case DNS::RR_type::TXT:
        break;
      case DNS::RR_type::TLSA:
        break;
      default:
        break;
      }
    }

    p = rr_p->next_rr_name();
  }

  LOG(INFO) << "*** nameservers == " << hdr_p->nscount();
  for (auto i = 0; i < hdr_p->nscount(); ++i) {
    std::string name;
    auto enc_len = 0;

    CHECK(expand_name(p, bfr, sz, name, &enc_len));
    p += enc_len;
    auto rr_p = reinterpret_cast<rr const*>(p);

    LOG(INFO) << "name == " << name;
    LOG(INFO) << "rr_p->type()  == " << DNS::RR_type_c_str(rr_p->rr_type());
    LOG(INFO) << "rr_p->class() == " << rr_p->rr_class();
    LOG(INFO) << "rr_p->ttl()   == " << rr_p->rr_ttl();

    p = rr_p->next_rr_name();
  }

  LOG(INFO) << "*** additional == " << hdr_p->arcount();
  for (auto i = 0; i < hdr_p->arcount(); ++i) {
    std::string name;
    auto enc_len = 0;

    CHECK(expand_name(p, bfr, sz, name, &enc_len));
    p += enc_len;
    auto rr_p = reinterpret_cast<rr const*>(p);

    if (rr_p->rr_type() == 41) {
      auto opt_p = reinterpret_cast<edns0_opt_meta_rr const*>(p);
      auto ext_rcode = (opt_p->extended_rcode() << 4) + hdr_p->rcode();
      LOG(INFO) << "extended rcode == " << DNS::rcode_c_str(ext_rcode);
    }
    else {
      LOG(INFO) << "name == " << name;
      LOG(INFO) << "rr_p->type()  == " << DNS::RR_type_c_str(rr_p->rr_type());
      LOG(INFO) << "rr_p->class() == " << rr_p->rr_class();
      LOG(INFO) << "rr_p->ttl()   == " << rr_p->rr_ttl();
    }

    p = rr_p->next_rr_name();
  }

  return true;
}

int main(int argc, char* argv[])
{
  static_assert(sizeof(header) == 12);
  static_assert(sizeof(question) == 4);
  static_assert(sizeof(edns0_opt_meta_rr) == 11);

  /*
  unsigned char test_bfr[300];
  CHECK_EQ(name_put(test_bfr, "foo.bar"), 9);
  CHECK_EQ(memcmp(test_bfr, "\03foo\03bar", 9), 0);

  CHECK_EQ(name_put(test_bfr, "."), 1);
  CHECK_EQ(memcmp(test_bfr, "", 1), 0);

  CHECK_EQ(name_put(test_bfr, ""), 1);
  CHECK_EQ(memcmp(test_bfr, "", 1), 0);

  CHECK_EQ(name_put(test_bfr, ".."), -1);

  CHECK_EQ(name_put(test_bfr, ".foo"), -1);

  CHECK_EQ(name_put(test_bfr, "foo."), 5);
  CHECK_EQ(memcmp(test_bfr, "\03foo", 5), 0);
  */

  auto ns_sock{[&] {
    auto tries = countof(nameservers);
    auto ns = std::experimental::randint(
        0, static_cast<int>(countof(nameservers) - 1));

    while (tries--) {

      // try the next one, with wrap
      if (++ns == countof(nameservers)) {
        ns = 0;
      }
      auto const& nameserver = nameservers[ns];

      auto const fd{socket(AF_INET, SOCK_STREAM, 0)};
      PCHECK(fd >= 0) << "socket() failed";

      uint16_t port = osutil::get_port(nameserver.port);

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
  }()};

  //.............................................................................

  auto constexpr name{"fuckall.digilicious.com"};

  uint16_t id = 0x1234;

  auto [q_buf, q_buflen] = create_question(name, DNS::RR_type::MX, id);
  LOG(INFO) << "q_buflen == " << q_buflen;

  uint16_t sz = q_buflen;
  sz = htons(sz);

  ns_sock->out().write(reinterpret_cast<char*>(&sz), sizeof sz);
  ns_sock->out().write(reinterpret_cast<char*>(q_buf.get()), q_buflen);
  ns_sock->out().flush();

  sz = 0;
  ns_sock->in().read(reinterpret_cast<char*>(&sz), sizeof sz);
  sz = ntohs(sz);
  LOG(INFO) << "read sz == " << sz;

  auto rd_bfr = std::make_unique<char[]>(sz);
  ns_sock->in().read(rd_bfr.get(), sz);

  parse_answer(reinterpret_cast<unsigned char const*>(rd_bfr.get()), sz);
}

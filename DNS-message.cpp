#include "DNS-message.hpp"

#include "DNS-iostream.hpp"
#include "Domain.hpp"

#include <arpa/nameser.h>

namespace {
using octet = DNS::message::octet;

octet constexpr lo(uint16_t n) { return octet(n & 0xFF); }
octet constexpr hi(uint16_t n) { return octet((n >> 8) & 0xFF); }

constexpr uint16_t as_u16(octet hi, octet lo)
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

  // clang-format off
  bool truncation()          const { return (flags_0_ & 0x02) != 0; }

  bool checking_disabled()   const { return (flags_1_ & 0x10) != 0; }
  bool authentic_data()      const { return (flags_1_ & 0x20) != 0; }
  bool recursion_available() const { return (flags_1_ & 0x80) != 0; }
  // clang-format on

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
    return static_cast<DNS::RR_type>(as_u16(qtype_hi_, qtype_lo_));
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
    return (uint32_t(ttl_0_) << 24) + (uint32_t(ttl_1_) << 16) +
           (uint32_t(ttl_2_) << 8) + (uint32_t(ttl_3_));
  }

  uint16_t rdlength() const { return as_u16(rdlength_hi_, rdlength_lo_); }

  auto cdata() const
  {
    return reinterpret_cast<char const*>(this) + sizeof(rr);
  }
  auto rddata() const { return reinterpret_cast<octet const*>(cdata()); }
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

int name_length(octet const* encoded, DNS::message const& pkt)
{
  auto const sp     = static_cast<std::span<DNS::message::octet const>>(pkt);
  auto const sp_end = sp.data() + sp.size();

  // Allow the caller to pass us buf + len and have us check for it.
  if (encoded >= sp_end)
    return -1;

  int length = 0;
  int nindir = 0; // count indirections

  while (*encoded) {

    auto const top = (*encoded & NS_CMPRSFLGS);

    if (top == NS_CMPRSFLGS) {
      // Check the offset and go there.
      if (encoded + 1 >= sp_end)
        return -1;

      unsigned const offset = (*encoded & ~NS_CMPRSFLGS) << 8 | *(encoded + 1);
      if (offset >= sp.size())
        return -1;

      encoded = sp.data() + offset;

      ++nindir;

      auto constexpr max_indirs = 50; // maximum indirections allowed for a name

      // If we've seen more indirects than the message length, or over
      // some limit, then there's a loop.
      if (nindir > std::streamsize(sp.size()) || nindir > max_indirs)
        return -1;
    }
    else if (top == 0) {
      auto offset = *encoded;
      if (encoded + offset + 1 >= sp_end)
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

bool expand_name(octet const*        encoded,
                 DNS::message const& pkt,
                 std::string&        name,
                 int&                enc_len)
{
  auto const sp = static_cast<std::span<DNS::message::octet const>>(pkt);

  name.clear();

  auto indir = false;

  auto const nlen = name_length(encoded, pkt);
  if (nlen < 0) {
    LOG(WARNING) << "bad name";
    return false;
  }

  name.reserve(nlen);

  if (nlen == 0) {
    // RFC 2181 says this should be ".": the root of the DNS tree.
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
        indir   = true;
      }
      p = sp.data() + ((*p & ~NS_CMPRSFLGS) << 8 | *(p + 1));
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

  if (name.length() && (name.back() == '.')) {
    name.pop_back();
  }

  return true;
}

// return the length of the encoded name

int name_put(octet* buf, char const* name)
{
  auto q = buf;

  if ((name[0] == '.') && (name[1] == '\0'))
    name++;

  while (*name) {
    if (*name == '.') {
      LOG(WARNING) << "zero length label";
      return -1;
    }

    uint8_t     len = 0;
    char const* p;

    for (p = name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      len++;
    }
    if (len > 63) {
      // RFC-1035 Section 2.3.4. Size limits
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

  auto const sz = q - buf;
  if (sz > 255) {
    // RFC-1035 Section 2.3.4. Size limits
    LOG(WARNING) << "domain name exceeds 255 octets";
    return -1;
  }

  return sz;
}
} // namespace

namespace DNS {

uint16_t message::id() const
{
  auto const hdr_p = reinterpret_cast<header const*>(buf_.data());
  return hdr_p->id();
}

size_t message::min_sz() { return sizeof(header); }

DNS::message
create_question(char const* name, DNS::RR_type type, uint16_t cls, uint16_t id)
{
  // size to allocate may be larger than needed if backslash escapes
  // are used in domain name

  auto const sz_alloc = strlen(name) + 2 + // clang-format off
                        sizeof(header)   +
                        sizeof(question) +
                        sizeof(edns0_opt_meta_rr); // clang-format on

  DNS::message::container_t buf(sz_alloc);

  auto q = buf.data();

  new (q) header(id);
  q += sizeof(header);

  auto const len = name_put(q, name);
  CHECK_GE(len, 1) << "malformed domain name " << name;
  q += len;

  new (q) question(type, cls);
  q += sizeof(question);

  new (q) edns0_opt_meta_rr(Config::max_udp_sz);
  q += sizeof(edns0_opt_meta_rr);

  // verify constructed size is less than or equal to allocated size
  auto const sz = q - buf.data();
  CHECK_LE(sz, sz_alloc);

  buf.resize(sz);
  buf.shrink_to_fit();

  return DNS::message{std::move(buf)};
}

void check_answer(bool& nx_domain,
                  bool& bogus_or_indeterminate,

                  uint16_t& rcode,
                  uint16_t& extended_rcode,

                  bool& truncation,
                  bool& authentic_data,
                  bool& has_record,

                  DNS::message const& q,
                  DNS::message const& a,

                  DNS::RR_type type,
                  char const*  name)
{
  // We grab some stuff from the question we generated.  This is not
  // an un-trusted datum from afar.

  auto const cls{[type = type, &q]() {
    auto const q_sp    = static_cast<std::span<DNS::message::octet const>>(q);
    auto       q_p     = q_sp.data();
    auto const q_hdr_p = reinterpret_cast<header const*>(q_p);
    CHECK_EQ(q_hdr_p->qdcount(), uint16_t(1));
    q_p += sizeof(header);
    std::string qname;
    int         name_len;
    CHECK(expand_name(q_p, q, qname, name_len));
    q_p += name_len;
    auto const question_p = reinterpret_cast<question const*>(q_p);
    CHECK(question_p->qtype() == type)
        << question_p->qtype() << " != " << type << '\n';
    return question_p->qclass();
  }()};

  auto const a_sp     = static_cast<std::span<DNS::message::octet const>>(a);
  auto const a_sp_end = a_sp.data() + a_sp.size();

  auto const hdr_p = reinterpret_cast<header const*>(a_sp.data());

  rcode = hdr_p->rcode();
  switch (rcode) {
  case ns_r_noerror: break;
  case ns_r_nxdomain: nx_domain = true; break;
  case ns_r_servfail: bogus_or_indeterminate = true; break;
  default:
    bogus_or_indeterminate = true;
    LOG(WARNING) << "name lookup error: " << DNS::rcode_c_str(rcode) << " for "
                 << name << '/' << type;
    break;
  }

  truncation     = hdr_p->truncation();
  authentic_data = hdr_p->authentic_data();
  has_record     = hdr_p->ancount() != 0;

  if (truncation) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "DNS answer truncated for " << name << '/' << type;
    return;
  }

  // check the question part of the reply

  if (hdr_p->qdcount() != 1) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "question not copied into answer for " << name << '/'
                 << type;
    return;
  }

  // p is a pointer that pushes forward in the message as we process
  // each section
  auto p = a_sp.data() + sizeof(header);

  { // make sure the question name matches
    std::string qname;
    auto        enc_len = 0;
    if (!expand_name(p, a, qname, enc_len)) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message";
      return;
    }
    p += enc_len;
    if (p >= a_sp_end) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message";
      return;
    }
    if (!Domain::match(qname, name)) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "names don't match, " << qname << " != " << name;
      return;
    }
  }

  if ((p + sizeof(question)) >= a_sp_end) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "bad message";
    return;
  }

  auto question_p = reinterpret_cast<question const*>(p);
  p += sizeof(question);

  if (question_p->qtype() != type) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "qtypes don't match, " << question_p->qtype()
                 << " != " << type;
    return;
  }
  if (question_p->qclass() != cls) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "qclasses don't match, " << question_p->qclass()
                 << " != " << cls;
    return;
  }

  // answers and nameservers
  for (auto i = 0; i < (hdr_p->ancount() + hdr_p->nscount()); ++i) {
    std::string x;
    auto        enc_len = 0;
    if (!expand_name(p, a, x, enc_len) ||
        ((p + enc_len + sizeof(rr)) > a_sp_end)) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message in answer or nameserver section for " << name
                   << '/' << type;
      return;
    }
    p += enc_len;
    auto const rr_p = reinterpret_cast<rr const*>(p);
    p               = rr_p->next_rr_name();
  }

  // check additional section for OPT record
  for (auto i = 0; i < hdr_p->arcount(); ++i) {
    std::string x;
    auto        enc_len = 0;
    if (!expand_name(p, a, x, enc_len) ||
        ((p + enc_len + sizeof(rr)) > a_sp_end)) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message in additional section for " << name << '/'
                   << type;
      return;
    }
    p += enc_len;
    auto const rr_p = reinterpret_cast<rr const*>(p);

    switch (rr_p->rr_type()) {
    case ns_t_opt: {
      auto opt_p     = reinterpret_cast<edns0_opt_meta_rr const*>(p);
      extended_rcode = (opt_p->extended_rcode() << 4) + hdr_p->rcode();
      break;
    }

    case ns_t_a:
    case ns_t_aaaa:
    case ns_t_ns:
    case ns_t_rrsig:
      // nameserver records often included with associated address info
      break;

    case ns_t_tlsa:
      // tlsa records can now be in the additioanl OPT section, as
      // they are returned from dns.mullvad.net.
      break;

    default:
      LOG(INFO) << "unknown additional record, name == " << name;
      LOG(INFO) << "rr_p->type()  == " << rr_p->rr_type() << " ("
                << RR_type_c_str(rr_p->rr_type()) << ")";
      LOG(INFO) << "rr_p->class() == " << rr_p->rr_class();
      LOG(INFO) << "rr_p->ttl()   == " << rr_p->rr_ttl();
      break;
    }

    p = rr_p->next_rr_name();
  }

  unsigned long size_check = p - a_sp.data();
  if (size_check != a_sp.size()) {
    bogus_or_indeterminate = true;
    LOG(WARNING) << "bad message size for " << name << '/' << type;
    return;
  }
}

std::optional<RR> get_A(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  if (rr_p->rdlength() != 4) {
    LOG(WARNING) << "bogus A record";
    err = true;
    return {};
  }
  return RR_A{rr_p->rddata(), rr_p->rdlength()};
}

std::optional<RR> get_CNAME(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  std::string name;
  int         enc_len;
  if (!expand_name(rr_p->rddata(), pkt, name, enc_len)) {
    LOG(WARNING) << "bogus CNAME record";
    err = true;
    return {};
  }
  return RR_CNAME{name};
}

std::optional<RR> get_PTR(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  std::string name;
  int         enc_len;
  if (!expand_name(rr_p->rddata(), pkt, name, enc_len)) {
    LOG(WARNING) << "bogus PTR record";
    err = true;
    return {};
  }
  return RR_PTR{name};
}

std::optional<RR> get_MX(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  std::string name;
  int         enc_len;
  if (rr_p->rdlength() < 3) {
    LOG(WARNING) << "bogus MX record";
    err = true;
    return {};
  }
  auto       p          = rr_p->rddata();
  auto const preference = as_u16(p[0], p[1]);
  p += 2;
  if (!expand_name(p, pkt, name, enc_len)) {
    LOG(WARNING) << "bogus MX record";
    err = true;
    return {};
  }
  return RR_MX{name, preference};
}

std::optional<RR> get_TXT(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  if (rr_p->rdlength() < 1) {
    LOG(WARNING) << "bogus TXT record";
    err = true;
    return {};
  }
  std::string str;
  auto        p = rr_p->rddata();
  do {
    if ((p + 1 + *p) > rr_p->next_rr_name()) {
      LOG(WARNING) << "bogus string in TXT record";
      err = true;
      return {};
    }
    str.append(reinterpret_cast<char const*>(p) + 1, *p);
    p += *p + 1;
  } while (p < rr_p->next_rr_name());
  return RR_TXT{str};
}

std::optional<RR> get_AAAA(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  if (rr_p->rdlength() != 16) {
    LOG(WARNING) << "bogus AAAA record";
    err = true;
    return {};
  }
  return RR_AAAA{rr_p->rddata(), rr_p->rdlength()};
}

std::optional<RR> get_RRSIG(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  // LOG(WARNING) << "#### FIXME! RRSIG";
  // return RR_RRSIG{rr_p->rddata(), rr_p->rdlength()});
  return {};
}

std::optional<RR> get_TLSA(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  if (rr_p->rdlength() < 4) {
    LOG(WARNING) << "bogus TLSA record";
    err = true;
    return {};
  }

  auto p = rr_p->rddata();

  uint8_t cert_usage    = *p++;
  uint8_t selector      = *p++;
  uint8_t matching_type = *p++;

  std::span<DNS::message::octet const> assoc_data{
      p, static_cast<size_t>(rr_p->rdlength()) - 3};

  return RR_TLSA{cert_usage, selector, matching_type, assoc_data};
}

std::optional<RR> get_rr(rr const* rr_p, DNS::message const& pkt, bool& err)
{
  auto const typ = static_cast<DNS::RR_type>(rr_p->rr_type());

  switch (typ) { // clang-format off
  case DNS::RR_type::A:     return get_A    (rr_p, pkt, err);
  case DNS::RR_type::CNAME: return get_CNAME(rr_p, pkt, err);
  case DNS::RR_type::PTR:   return get_PTR  (rr_p, pkt, err);
  case DNS::RR_type::MX:    return get_MX   (rr_p, pkt, err);
  case DNS::RR_type::TXT:   return get_TXT  (rr_p, pkt, err);
  case DNS::RR_type::AAAA:  return get_AAAA (rr_p, pkt, err);
  case DNS::RR_type::RRSIG: return get_RRSIG(rr_p, pkt, err);
  case DNS::RR_type::TLSA:  return get_TLSA (rr_p, pkt, err);
  default: break;
  } // clang-format on

  LOG(WARNING) << "unsupported RR type " << typ;
  return {};
}

RR_collection get_records(message const& pkt, bool& bogus_or_indeterminate)
{
  auto const sp     = static_cast<std::span<DNS::message::octet const>>(pkt);
  auto const sp_end = sp.data() + sp.size();

  RR_collection ret;

  auto const hdr_p = reinterpret_cast<header const*>(sp.data());

  auto p = sp.data() + sizeof(header);

  // skip queries
  for (auto i = 0; i < hdr_p->qdcount(); ++i) {
    std::string qname;
    auto        enc_len = 0;

    CHECK(expand_name(p, pkt, qname, enc_len));
    p += enc_len;
    // auto question_p = reinterpret_cast<question const*>(p);
    p += sizeof(question);
  }

  // get answers
  for (auto i = 0; i < hdr_p->ancount(); ++i) {
    std::string name;
    auto        enc_len = 0;
    CHECK(expand_name(p, pkt, name, enc_len));
    p += enc_len;
    if ((p + sizeof(rr)) > sp_end) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message";
      return RR_collection{};
    }
    auto rr_p = reinterpret_cast<rr const*>(p);
    if ((p + rr_p->rdlength()) > sp_end) {
      bogus_or_indeterminate = true;
      LOG(WARNING) << "bad message";
      return RR_collection{};
    }

    auto rr_ret = get_rr(rr_p, pkt, bogus_or_indeterminate);

    if (bogus_or_indeterminate)
      return RR_collection{};

    if (rr_ret)
      ret.emplace_back(*rr_ret);

    p = rr_p->next_rr_name();
  }

  return ret;
}

} // namespace DNS

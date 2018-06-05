#include "DNS.hpp"
#include "POSIX.hpp"
#include "Sock.hpp"

#include <memory>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#include <glog/logging.h>

auto constexpr tor_host{"127.0.0.1"};
auto constexpr tor_port{9050};

using octet = unsigned char;

octet constexpr lo(uint16_t n) { return octet(n & 0xFF); }
octet constexpr hi(uint16_t n) { return octet((n >> 8) & 0xFF); }

enum class auth_method : uint8_t {
  no_auth = 0,
  none = 0xff,
};

constexpr char const* c_str(auth_method auth)
{
  switch (auth) {
  case auth_method::no_auth:
    return "no authentication required";
  case auth_method::none:
    return "no acceptable methods";
  }
  return "*** unknown auth_method ***";
}

std::ostream& operator<<(std::ostream& os, auth_method const& auth)
{
  return os << c_str(auth);
}

class greeting {
  octet version_{5};
  octet nmethod_{1};
  auth_method method_{auth_method::no_auth};
};

class response {
  octet version_;
  auth_method method_;

public:
  auto version() const { return version_; }
  auto method() const { return method_; }
};

enum class command : octet {
  connect = 1,
  bind = 2,
  udp_associate = 3,
};

constexpr char const* c_str(command cmd)
{
  switch (cmd) {
  case command::connect:
    return "connect";
    break;
  case command::bind:
    return "bind";
    break;
  case command::udp_associate:
    return "UDP associate";
    break;
  }
  return "*** unknown command ***";
}

std::ostream& operator<<(std::ostream& os, command const& cmd)
{
  return os << c_str(cmd);
}

enum class address_type : octet {
  ip4_address = 1,
  domain_name = 3,
  ip6_address = 4,
};

constexpr char const* c_str(address_type at)
{
  switch (at) {
  case address_type::ip4_address:
    return "IPv4 address";
    break;
  case address_type::domain_name:
    return "domain name";
    break;
  case address_type::ip6_address:
    return "IPv6 address";
    break;
  }
  return "*** unknown address type ***";
}

std::ostream& operator<<(std::ostream& os, address_type const& at)
{
  return os << c_str(at);
}

class request4 {
  octet version_{5};
  command cmd_{command::connect};
  octet reserved_{0};
  address_type typ_{address_type::ip4_address};
  octet ip4_[4];
  octet port_hi_;
  octet port_lo_;

public:
  void addr(char const* addr)
  {
    CHECK_EQ(inet_pton(AF_INET, addr, reinterpret_cast<void*>(ip4_)), 1);
  }
  void port(uint16_t port)
  {
    port_hi_ = hi(port);
    port_lo_ = lo(port);
  }
};

enum class reply_field : octet {
  succeeded,
  server_failure,
  not_allowed,
  network_unreachable,
  host_unreachable,
  connection_refused,
  TTL_expired,
  command_not_supported,
  address_type_not_supported,
};

constexpr char const* c_str(reply_field rp)
{
  switch (rp) {
  case reply_field::succeeded:
    return "succeeded";
    break;
  case reply_field::server_failure:
    return "server_failure";
    break;
  case reply_field::not_allowed:
    return "not_allowed";
    break;
  case reply_field::network_unreachable:
    return "network_unreachable";
    break;
  case reply_field::host_unreachable:
    return "host_unreachable";
    break;
  case reply_field::connection_refused:
    return "connection_refused";
    break;
  case reply_field::TTL_expired:
    return "TTL_expired";
    break;
  case reply_field::command_not_supported:
    return "command_not_supported";
    break;
  case reply_field::address_type_not_supported:
    return "address_type_not_supported";
    break;
  }
  return "*** unknown reply field ***";
}

std::ostream& operator<<(std::ostream& os, reply_field const& rp)
{
  return os << c_str(rp);
}

class reply4 {
  octet version_;
  reply_field rep_;
  octet reserved_;
  address_type typ_;
  octet ip4_[4];
  octet port_lo_;
  octet port_hi_;

public:
  auto version() const { return version_; }
  auto rep() const { return rep_; }
  auto typ() const { return typ_; }
  std::string addr() const
  {
    std::string a;
    a.resize(16);
    CHECK_NOTNULL(inet_ntop(AF_INET, reinterpret_cast<void const*>(ip4_), &a[0],
                            a.size()));
    return a;
  }
  uint16_t port() const { return (port_hi_ << 8) + port_lo_; }
};

DNS::RR_set
get_tlsa_rrs(DNS::Resolver& res, Domain const& domain, uint16_t port)
{
  CHECK(!domain.ascii().empty());

  std::ostringstream tlsa;
  tlsa << '_' << port << "._tcp." << domain.ascii();

  DNS::Query q(res, DNS::RR_type::TLSA, tlsa.str());

  if (q.nx_domain()) {
    LOG(INFO) << "TLSA data not found for " << domain << ':' << port;
  }

  auto tlsa_rrs = q.get_records();

  if (q.bogus_or_indeterminate()) {
    LOG(WARNING) << "TLSA data bogus_or_indeterminate";
    tlsa_rrs.clear();
  }

  return tlsa_rrs;
}

int main(int argc, char* argv[])
{
  auto const fd = socket(AF_INET, SOCK_STREAM, 0);
  PCHECK(fd >= 0) << "socket() failed";

  auto in4{sockaddr_in{}};
  in4.sin_family = AF_INET;
  in4.sin_port = htons(tor_port);
  CHECK_EQ(inet_pton(AF_INET, tor_host, reinterpret_cast<void*>(&in4.sin_addr)),
           1);
  PCHECK(connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4)) == 0)
      << "connect failed: ";

  greeting grtng;

  PCHECK(write(fd, &grtng, sizeof(grtng)) == sizeof(grtng))
      << "greeting write failed: ";

  response rspns;

  PCHECK(read(fd, &rspns, sizeof(rspns)) == sizeof(rspns))
      << "response read failed: ";

  CHECK_EQ(rspns.version(), 5);
  CHECK_EQ(rspns.method(), auth_method::no_auth);

  auto constexpr domain{"digilicious.com"};
  uint16_t constexpr port{443};

  request4 request;

  request.port(port);
  request.addr("108.83.36.113");

  PCHECK(write(fd, reinterpret_cast<char*>(&request), sizeof(request4))
         == sizeof(request4))
      << "request write failed: ";

  reply4 reply;

  PCHECK(read(fd, reinterpret_cast<char*>(&reply), sizeof(reply4))
         == sizeof(reply4))
      << "reply read failed: ";

  CHECK_EQ(reply.version(), 5);
  CHECK_EQ(reply.rep(), reply_field::succeeded);
  CHECK_EQ(reply.typ(), address_type::ip4_address);

  LOG(INFO) << "connected to " << reply.addr() << ':' << reply.port() << '\n';

  POSIX::set_nonblocking(fd);
  Sock sock(fd, fd);

  DNS::Resolver res;
  auto tlsa_rrs = get_tlsa_rrs(res, Domain(domain), port);

  LOG(INFO) << "starting TLS";

  sock.starttls_client(nullptr, domain, tlsa_rrs, !tlsa_rrs.empty());

  sock.out() << "GET / HTTP/1.1\r\nHost: digilicious.com\r\n\r\n" << std::flush;

  std::string line;
  while (std::getline(sock.in(), line)) {
    std::cout << line << '\n';
    if (line == "</html>")
      break;
  }
}

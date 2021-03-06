#include "DNS.hpp"
#include "POSIX.hpp"
#include "Sock.hpp"
#include "osutil.hpp"

#include <cstddef>
#include <memory>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#include <glog/logging.h>

#include <fmt/format.h>

#define CRLF "\r\n"

constexpr auto socks_version = 5;

namespace {
using octet = uint8_t;

octet constexpr lo(uint16_t n) { return octet(n & 0xFF); }
octet constexpr hi(uint16_t n) { return octet((n >> 8) & 0xFF); }

enum class auth_method : octet {
  no_auth = 0,
  none    = 0xff,
};

constexpr char const* c_str(auth_method auth)
{
  switch (auth) {
  case auth_method::no_auth: return "no authentication required";
  case auth_method::none: return "no acceptable methods";
  }
  return "*** unknown auth_method ***";
}

std::ostream& operator<<(std::ostream& os, auth_method const& auth)
{
  return os << c_str(auth);
}

class greeting {
  octet       version_{socks_version};
  octet       nmethod_{1};
  auth_method method_{auth_method::no_auth};
};

class response {
  octet       version_;
  auth_method method_;

public:
  auto version() const { return version_; }
  auto method() const { return method_; }
};

enum class command : octet {
  connect       = 1,
  bind          = 2,
  udp_associate = 3,
};

constexpr char const* c_str(command cmd)
{
  switch (cmd) {
  case command::connect: return "connect";
  case command::bind: return "bind";
  case command::udp_associate: return "UDP associate";
  }
  return "*** unknown command ***";
}

enum class address_type : octet {
  ip4_address = 1,
  domain_name = 3,
  ip6_address = 4,
};

constexpr char const* c_str(address_type at)
{
  switch (at) {
  case address_type::ip4_address: return "IPv4 address";
  case address_type::domain_name: return "domain name";
  case address_type::ip6_address: return "IPv6 address";
  }
  return "*** unknown address type ***";
}

std::ostream& operator<<(std::ostream& os, address_type const& at)
{
  return os << c_str(at);
}

class request_domain {
  octet        version_{socks_version};
  command      cmd_{command::connect};
  octet        reserved_{0};
  address_type typ_{address_type::domain_name};
  octet        var_[258]; // 255 + 1 + 2

public:
  request_domain(char const* addr, uint16_t port)
  {
    auto const len = strlen(addr);
    CHECK_LE(len, 255);
    var_[0] = static_cast<octet>(len);
    memcpy(var_ + 1, addr, len);
    var_[len + 1] = hi(port);
    var_[len + 2] = lo(port);
  }

  ssize_t size() const { return offsetof(request_domain, var_) + var_[0] + 3; }
};

class request4 {
  octet        version_{socks_version};
  command      cmd_{command::connect};
  octet        reserved_{0};
  address_type typ_{address_type::ip4_address};
  octet        ip4_[4];
  octet        port_hi_;
  octet        port_lo_;

  void addr_(char const* addr)
  {
    CHECK_EQ(inet_pton(AF_INET, addr, reinterpret_cast<void*>(ip4_)), 1);
  }
  void port_(uint16_t port)
  {
    port_hi_ = hi(port);
    port_lo_ = lo(port);
  }

public:
  request4(char const* addr, uint16_t port)
  {
    addr_(addr);
    port_(port);
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
  case reply_field::succeeded: return "succeeded";
  case reply_field::server_failure: return "server_failure";
  case reply_field::not_allowed: return "not_allowed";
  case reply_field::network_unreachable: return "network_unreachable";
  case reply_field::host_unreachable: return "host_unreachable";
  case reply_field::connection_refused: return "connection_refused";
  case reply_field::TTL_expired: return "TTL_expired";
  case reply_field::command_not_supported: return "command_not_supported";
  case reply_field::address_type_not_supported:
    return "address_type_not_supported";
  }
  return "*** unknown reply field ***";
}

std::ostream& operator<<(std::ostream& os, reply_field const& rp)
{
  return os << c_str(rp);
}

class reply4 {
  octet        version_;
  reply_field  reply_;
  octet        reserved_;
  address_type type_;
  octet        ip4_[4];
  octet        port_lo_;
  octet        port_hi_;

public:
  auto version() const { return version_; }
  auto reply() const { return reply_; }
  auto type() const { return type_; }

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

DNS::RR_collection
get_tlsa_rrs(DNS::Resolver& res, Domain const& domain, uint16_t port)
{
  CHECK(!domain.ascii().empty());

  auto const tlsa{fmt::format("_{:d}._tcp.{}", port, domain.ascii())};

  DNS::Query q(res, DNS::RR_type::TLSA, tlsa);

  if (q.nx_domain()) {
    LOG(INFO) << "TLSA data not found for " << domain << ':' << port;
  }

  auto const tlsa_rrs{q.get_records()};

  if (q.bogus_or_indeterminate()) {
    LOG(WARNING) << "TLSA data bogus_or_indeterminate";
  }

  return tlsa_rrs;
}

template <class T>
void read_checked(int fd, T& obj, std::string_view msg)
{
  PCHECK(read(fd, &obj, sizeof(obj)) == sizeof(obj)) << msg;
}

template <class T>
void write_checked(int fd, T const& obj, std::string_view msg)
{
  PCHECK(write(fd, &obj, sizeof(obj)) == sizeof(obj)) << msg;
}
} // namespace

int main(int argc, char* argv[])
{
  auto const fd = socket(AF_INET, SOCK_STREAM, 0);
  PCHECK(fd >= 0) << "socket() failed";

  auto constexpr tor_host{"127.0.0.1"};
  auto constexpr tor_port{9050};

  auto in4{sockaddr_in{}};
  in4.sin_family = AF_INET;
  in4.sin_port   = htons(tor_port);
  CHECK_EQ(inet_pton(AF_INET, tor_host, reinterpret_cast<void*>(&in4.sin_addr)),
           1);
  PCHECK(connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4)) == 0)
      << "connect failed: ";

  greeting grtng;
  write_checked(fd, grtng, "greeting write failed");

  response rspns;
  read_checked(fd, rspns, "response read failed");

  CHECK_EQ(rspns.version(), socks_version);
  CHECK_EQ(rspns.method(), auth_method::no_auth);

  auto constexpr domain{"digilicious.com"};
  uint16_t constexpr port{443};

  // request4 request("108.83.36.113", port);
  request_domain request(domain, port);
  PCHECK(write(fd, &request, request.size()) == request.size())
      << "request write failed";

  reply4 reply;
  read_checked(fd, reply, "reply read failed");

  CHECK_EQ(reply.version(), socks_version);
  CHECK_EQ(reply.reply(), reply_field::succeeded);
  CHECK_EQ(reply.type(), address_type::ip4_address);

  LOG(INFO) << "connected to " << reply.addr() << ':' << reply.port() << '\n';

  POSIX::set_nonblocking(fd);
  Sock sock(fd, fd);

  auto const    config_dir = osutil::get_config_dir();
  DNS::Resolver res(config_dir);
  auto          tlsa_rrs = get_tlsa_rrs(res, Domain(domain), port);

  LOG(INFO) << "starting TLS";

  sock.starttls_client(config_dir, nullptr, domain, tlsa_rrs,
                       !tlsa_rrs.empty());

  sock.out() << "GET / HTTP/1.1" CRLF "Host: " << domain << CRLF CRLF
             << std::flush;

  std::string line;
  while (std::getline(sock.in(), line)) {
    std::cout << line << '\n';
    if (line == "</html>")
      break;
  }
}

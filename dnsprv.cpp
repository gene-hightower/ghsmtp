#include <memory>

#include <experimental/random>

#include <ares.h>

#include <glog/logging.h>

#include <arpa/nameser.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "Sock.hpp"
#include "osutil.hpp"

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
  return N;
}

// convert binary input into a std::string of hex digits

auto bin2hexstring(char const* data, size_t length)
{
  std::string ret;
  ret.reserve(2 * length + 1);

  for (size_t n = 0u; n < length; ++n) {
    auto const ch = data[n];

    auto const lo = ch & 0xF;
    auto const hi = (ch >> 4) & 0xF;

    auto constexpr hex_digits = "0123456789abcdef";

    ret += hex_digits[hi];
    ret += hex_digits[lo];
  }

  return ret;
}

struct nameserver {
  char const* host;
  char const* addr;
  char const* port;
};

constexpr nameserver nameservers[]
{
#if 1
  {
      "localhost",
      "127.0.0.1",
      "domain",
  },
#else
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
#endif
};

int main(int argc, char* argv[])
{
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

      auto const sock = std::make_shared<Sock>(fd, fd);

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

  ares_library_init(ARES_LIB_INIT_ALL);

  auto dnsclass = ns_c_in;
  auto type = ns_t_a;
  auto id = 0x1234;

  unsigned char* buf = nullptr;
  auto buflen = 0;

  auto name = "amazon.com";

  auto ret = ares_create_query(name, dnsclass, type, id, 1, &buf, &buflen, 0);

  CHECK_EQ(ret, ARES_SUCCESS);
  LOG(INFO) << "write buflen == " << buflen;

  uint16_t sz = buflen;
  sz = htons(sz);

  ns_sock->out().write(reinterpret_cast<char*>(&sz), sizeof sz);
  ns_sock->out().write(reinterpret_cast<char*>(buf), buflen);
  ns_sock->out().flush();

  ns_sock->in().read(reinterpret_cast<char*>(&sz), sizeof sz);

  sz = ntohs(sz);

  LOG(INFO) << "read sz == " << sz;

  auto rd_bfr = std::make_unique<char[]>(sz);

  ns_sock->in().read(rd_bfr.get(), sz);

  auto str = bin2hexstring(rd_bfr.get(), sz);
  LOG(INFO) << str;

  struct hostent* he = nullptr;
  ret = ares_parse_a_reply(reinterpret_cast<unsigned char*>(rd_bfr.get()), sz,
                           &he, nullptr, nullptr);
  CHECK_EQ(ret, ARES_SUCCESS);

  ares_free_hostent(he);
}

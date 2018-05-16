#include <memory>

#include <experimental/random>

#include "Sock.hpp"
#include "osutil.hpp"

#include <glog/logging.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

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
};

int main(int argc, char* argv[])
{
  auto sock{[&] {
    auto tries = countof(nameservers);
    auto ns = std::experimental::randint(
        0, static_cast<int>(countof(nameservers) - 1));

    while (tries--) {
      // try the next one, with wrap
      if (++ns == countof(nameservers)) {
        ns = 0;
      }

      auto const fd{socket(AF_INET, SOCK_STREAM, 0)};
      PCHECK(fd >= 0) << "socket() failed";

      uint16_t port = osutil::get_port(nameservers[ns].port);

      auto in4{sockaddr_in{}};
      in4.sin_family = AF_INET;
      in4.sin_port = htons(port);
      CHECK_EQ(inet_pton(AF_INET, nameservers[ns].addr,
                         reinterpret_cast<void*>(&in4.sin_addr)),
               1);
      if (connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4))) {
        PLOG(INFO) << "connect failed " << nameservers[ns].host << '['
                   << nameservers[ns].addr << "]:" << nameservers[ns].port;
        close(fd);
        continue;
      }
      auto sock = std::make_shared<Sock>(fd, fd);
      DNS::RR_set tlsa_rrs; // empty
      sock->starttls_client(nullptr, nameservers[ns].host, tlsa_rrs, false);
      if (sock->verified()) {
        LOG(INFO) << "using " << nameservers[ns].host << '['
                  << nameservers[ns].addr << "]:" << nameservers[ns].port;
        return sock;
      }

      close(fd);
    }

    LOG(FATAL) << "no nameservers left to try";
  }()};
}

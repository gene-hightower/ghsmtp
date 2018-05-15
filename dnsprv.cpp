#include <iostream>

#include "Sock.hpp"
#include "osutil.hpp"

#include <glog/logging.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

auto constexpr addr4 = "1.1.1.1";
auto constexpr srv = "domain-s";

auto constexpr client_name = "digilicious.com";
auto constexpr server_name = "1dot1dot1dot1.cloudflare-dns.com";

int main(int argc, char* argv[])
{
  uint16_t port = osutil::get_port(srv);

  auto const fd{socket(AF_INET, SOCK_STREAM, 0)};
  PCHECK(fd >= 0) << "socket() failed";

  auto in4{sockaddr_in{}};
  in4.sin_family = AF_INET;
  in4.sin_port = htons(port);
  CHECK_EQ(inet_pton(AF_INET, addr4, reinterpret_cast<void*>(&in4.sin_addr)),
           1);

  if (connect(fd, reinterpret_cast<const sockaddr*>(&in4), sizeof(in4))) {
    PLOG(FATAL) << "connect failed [" << addr4 << "]:" << port;
  }

  Sock sock(fd, fd);

  DNS::RR_set tlsa_rrs; // empty

  sock.starttls_client(client_name, server_name, tlsa_rrs, false);
  CHECK(sock.verified());
}

/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2016 Gene Hightower <ghsmtp@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3 of the
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  If not, see
    <http://www.gnu.org/licenses/>.

*/

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>

#include "IP4.hpp"

enum class P0fMagic : uint32_t {
  UNKNOWN = 0,
  QUERY = 0x50304601,
  RESP = 0x50304602,
};

enum class P0fStatus : uint32_t {
  BADQUERY = 0x00,
  OK = 0x10,
  NOMATCH = 0x20,
};

enum class P0fAddr : uint8_t {
  UNKNOWN = 0,
  IPV4 = 4,
  IPV6 = 6,
};

constexpr size_t P0F_STR_MAX = 31;

constexpr auto P0F_MATCH_FUZZY = 1;
constexpr auto P0F_MATCH_GENERIC = 2;

struct p0f_api_query {

  P0fMagic const magic{P0fMagic::QUERY};
  P0fAddr addr_type{P0fAddr::UNKNOWN};
  uint8_t addr[16]{0};

} __attribute__((packed));

struct p0f_api_response {

  P0fMagic const magic{P0fMagic::UNKNOWN};
  P0fStatus status;

  uint32_t first_seen; // First seen (unix time)
  uint32_t last_seen;  // Last seen (unix time)
  uint32_t total_conn; // Total connections seen

  uint32_t uptime_min;  // Last uptime (minutes)
  uint32_t up_mod_days; // Uptime modulo (days)

  uint32_t last_nat; // NAT / LB last detected (unix time)
  uint32_t last_chg; // OS chg last detected (unix time)

  int16_t distance; // System distance

  uint8_t bad_sw;     // Host is lying about U-A / Server
  uint8_t os_match_q; // Match quality

  char os_name[P0F_STR_MAX + 1];     // Name of detected OS
  char os_flavor[P0F_STR_MAX + 1];   // Flavor of detected OS
  char http_name[P0F_STR_MAX + 1];   // Name of detected HTTP app
  char http_flavor[P0F_STR_MAX + 1]; // Flavor of detected HTTP app
  char link_type[P0F_STR_MAX + 1];   // Link type
  char language[P0F_STR_MAX + 1];    // Language

} __attribute__((packed));

int main(int argc, char const* argv[])
{
  for (auto i = 1; i < argc; ++i) {
    if (IP4::is_address(argv[i])) {

      p0f_api_query q;

      if (inet_pton(AF_INET, argv[i], reinterpret_cast<void*>(&q.addr)) == 1) {
        q.addr_type = P0fAddr::IPV4;
        auto fd = socket(AF_UNIX, SOCK_STREAM, 0);
        PCHECK(fd >= 0) << "open failed";

        sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/run/p0f.sock", sizeof(addr.sun_path) - 1);

        PCHECK(
            connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr))
            >= 0);

        PCHECK(write(fd, reinterpret_cast<void const*>(&q), sizeof(q)))
            << "p0f api write failed";

        p0f_api_response r;

        PCHECK(read(fd, reinterpret_cast<void*>(&r), sizeof(r)))
            << "p0f api read failed";

        PCHECK(close(fd) >= 0) << "p0f api close failed";

        CHECK(r.magic == P0fMagic::RESP);

        switch (r.status) {
        case P0fStatus::BADQUERY:
          LOG(ERROR) << "bad query";
          break;
        case P0fStatus::OK:
          std::cout << "os_match_q == " << static_cast<int>(r.os_match_q)
                    << "\n";
          std::cout << "os_name    == " << r.os_name << "\n";
          std::cout << "os_flavor  == " << r.os_flavor << "\n";
          break;
        case P0fStatus::NOMATCH:
          LOG(ERROR) << "no match";
          break;
        }
      }
    }
  }
}

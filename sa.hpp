#ifndef SA_DOT_HPP_INCLUDED
#define SA_DOT_HPP_INCLUDED

#include <arpa/inet.h>
#include <netinet/in.h>

namespace sa {
union sockaddrs {
  struct sockaddr addr;
  struct sockaddr_in addr_in;
  struct sockaddr_in6 addr_in6;
  struct sockaddr_storage addr_storage;
};
} // namespace sa

#endif // SA_DOT_HPP_INCLUDED

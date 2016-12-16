/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>
*/

// scratch program to mess with getaddrinfo

#include <cstdlib>
#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>

#include <glog/logging.h>

using namespace google;
using namespace std;

int main(int argc, char* argv[])
{
  InitGoogleLogging(argv[0]);
  InstallFailureSignalHandler();

  if (1 == argc) {
    return 0;
  }

  addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_protocol = 0; // any protocol

  addrinfo* result;
  int err = getaddrinfo(argv[1], nullptr, &hints, &result);
  if (err) {
    cerr << "getaddrinfo failure: " << gai_strerror(err) << endl;
    return 1;
  }

  if (0 == result) {
    cerr << "no results" << endl;
    return 2;
  }

  for (addrinfo* rp = result; rp; rp = rp->ai_next) {
    switch (rp->ai_family) {
    case AF_INET:
      cout << "AF_INET";
      break;
    case AF_INET6:
      cout << "AF_INET6";
      break;
    default:
      cout << "unknown ai_family " << rp->ai_family << endl;
      return 3;
    }

    switch (rp->ai_socktype) {
    case SOCK_STREAM:
      cout << " SOCK_STREAM";
      break;
    case SOCK_DGRAM:
      cout << " SOCK_DGRAM";
      break;
    default:
      cout << "unknown ai_socktype " << rp->ai_socktype << endl;
      return 4;
    }

    switch (rp->ai_protocol) {
    case IPPROTO_TCP:
      cout << " IPPROTO_TCP";
      break;
    case IPPROTO_UDP:
      cout << " IPPROTO_UDP";
      break;
    default:
      cout << "unknown ai_protocol " << rp->ai_protocol << endl;
      return 5;
    }

    cout << endl;

    if (rp->ai_canonname)
      cout << "canonname == " << rp->ai_canonname << endl;

    char net_addr[INET6_ADDRSTRLEN];

    switch (rp->ai_addrlen) {
    case sizeof(sockaddr_in): {
      CHECK(rp->ai_family == AF_INET);
      sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
      inet_ntop(AF_INET, &(sa->sin_addr), net_addr, sizeof net_addr);
      break;
    }
    case sizeof(sockaddr_in6): {
      CHECK(rp->ai_family == AF_INET6);
      sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
      inet_ntop(AF_INET6, &(sa->sin6_addr), net_addr, sizeof net_addr);
      break;
    }
    default:
      cout << "unknown ai_addrlen" << rp->ai_addrlen << endl;
      return 6;
    }

    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];

    cout << "addr      == " << net_addr << endl;

    if (AF_INET == rp->ai_family) {
      sockaddr_in adr;
      adr.sin_family = AF_INET;
      PCHECK(inet_pton(AF_INET, net_addr, &adr.sin_addr) == 1);
      err = getnameinfo(reinterpret_cast<sockaddr*>(&adr), sizeof adr, host,
                        sizeof host, serv, sizeof serv, 0);
      if (err) {
        cerr << "4 getnameinfo failure: " << gai_strerror(err) << endl;
        return 7;
      }
    }

    if (AF_INET6 == rp->ai_family) {
      sockaddr_in6 adr;
      adr.sin6_family = AF_INET6;
      PCHECK(inet_pton(AF_INET6, net_addr, &adr.sin6_addr) == 1);
      err = getnameinfo(reinterpret_cast<sockaddr*>(&adr), sizeof adr, host,
                        sizeof host, serv, sizeof serv, 0);
      if (err) {
        cerr << "6 getnameinfo failure: " << gai_strerror(err) << endl;
        return 8;
      }
    }

    cout << "reverse   == " << host << endl;
  }

  freeaddrinfo(result);
}

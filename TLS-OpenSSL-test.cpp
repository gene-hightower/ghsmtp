#include "TLS-OpenSSL.hpp"

#include <glog/logging.h>

#include <iostream>

int main(int argc, char* argv[])
{
  auto const read_hook = []() {};
  TLS        tls(read_hook);

  std::cout << "sizeof(TLS) == " << sizeof(TLS) << '\n';
}

/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
*/

#include "TLS-OpenSSL.hpp"

#include <glog/logging.h>

#include <iostream>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  TLS tls;

  std::cout << "sizeof(TLS) == " << sizeof(TLS) << '\n';
}

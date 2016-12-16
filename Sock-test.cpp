/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>
*/

#include <iostream>

#include "Sock.hpp"

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Sock sock(STDIN_FILENO, STDOUT_FILENO);

  char const* us = sock.us_c_str();
  if (*us) {
    std::cout << us << '\n';
  }

  char const* them = sock.them_c_str();
  if (*them) {
    std::cout << them << '\n';
  }

  std::cout << "sizeof(Sock) == " << sizeof(Sock) << '\n';
}

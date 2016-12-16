/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>
*/

#include "SockDevice.hpp"

#include <glog/logging.h>

#include <fcntl.h>

#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
  std::cout << "sizeof(SockDevice) == " << sizeof(SockDevice) << '\n';
}

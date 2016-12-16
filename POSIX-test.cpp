/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
*/

#include "POSIX.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  POSIX::set_nonblocking(0);

  CHECK(!POSIX::input_ready(0, std::chrono::milliseconds(1)));
  CHECK(POSIX::output_ready(1, std::chrono::milliseconds(1)));
}

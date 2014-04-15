/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "Session.hpp"

#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct Session_test {
  void test()
  {
    int fd_null = open("/dev/null", O_WRONLY);
    PCHECK(fd_null >= 0) << " can't open /dev/null";

    Session sess(STDIN_FILENO, fd_null, "example.com");

    CHECK(!sess.verify_sender_domain("com"));
    CHECK(!sess.verify_sender_domain("zzux.com"));
    CHECK(!sess.verify_sender_domain("blogspot.com.ar"));

    std::cout << "sizeof(Session) == " << sizeof(Session) << std::endl;
  }
};

int main(int argc, char* argv[])
{
  Logging::init(argv[0]);

  Session_test t;
  t.test();
}

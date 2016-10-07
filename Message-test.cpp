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

#include "Message.hpp"

#include <iostream>

#include <cstdlib>
#include <sys/utsname.h>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  char env[100] = "MAILDIR=/tmp/Maildir";
  PCHECK(putenv(env) == 0);

  Message msg("example.com");

  msg.out() << "foo bar baz";
  msg.save();

  Message msg2("example.com");

  CHECK(msg.id() != msg2.id());

  std::stringstream msg_str, msg2_str;

  msg_str << msg.id();
  msg2_str << msg2.id();

  CHECK_NE(msg_str.str(), msg2_str.str());

  msg2.trash();

  std::cout << "sizeof(Message) == " << sizeof(Message) << '\n';
}

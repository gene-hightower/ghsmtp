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

#include "Pill.hpp"

#include <iostream>
#include <string.h>

int main(int arcv, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  std::random_device rd;

  Pill red(rd), blue(rd);
  CHECK(red != blue);

  std::stringstream red_str, blue_str;

  red_str << red;
  blue_str << blue;

  CHECK_NE(red_str.str(), blue_str.str());

  CHECK_EQ(13U, red_str.str().length());
  CHECK_EQ(13U, blue_str.str().length());

  Pill red2(red);
  CHECK_EQ(red, red2);

  std::cout << "sizeof(Pill) == " << sizeof(Pill) << std::endl;
}

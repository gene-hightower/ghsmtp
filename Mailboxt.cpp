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

#include "Mailbox.hpp"

#include <iostream>

#include <glog/logging.h>

#include <boost/lexical_cast.hpp>

int main(int argc, char* argv[])
{
  Logging::init(argv[0]);

  Mailbox mb;
  CHECK(mb.empty());

  Mailbox dg{"gene", "digilicious.com"};

  CHECK_EQ(std::string("digilicious.com"), dg.domain());

  std::string dgstr = boost::lexical_cast<std::string>(dg);

  CHECK_EQ(dgstr, "gene@digilicious.com");

  dg.clear();
  CHECK(dg.empty());

  std::cout << "sizeof(Mailbox) == " << sizeof(Mailbox) << std::endl;
}

/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#include "Mailbox.hpp"

#include <iostream>

#include <glog/logging.h>

#include <boost/lexical_cast.hpp>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Mailbox mb;
  CHECK(mb.empty());

  Mailbox dg{"gene", "digilicious.com"};

  CHECK_EQ(std::string("digilicious.com"), dg.domain());

  std::string dgstr = boost::lexical_cast<std::string>(dg);

  CHECK_EQ(dgstr, "gene@digilicious.com");

  dg.clear();
  CHECK(dg.empty());

  std::cout << "sizeof(Mailbox) == " << sizeof(Mailbox) << '\n';
}

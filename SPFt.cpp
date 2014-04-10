/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

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

#include "SPF.hpp"

#include <iostream>

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  CHECK_EQ(sizeof(SPF::Server), sizeof(void*));
  CHECK_EQ(sizeof(SPF::Request), sizeof(void*));

  SPF::Server srv("EXAMPLE.COM");
  SPF::Request req(srv);
  req.set_ipv4_str("108.83.36.113");
  req.set_helo_dom("digilicious.com");
  req.set_env_from("postmaster@digilicious.com");

  SPF::Result res = req.check();
  std::cout << "result == " << SPF::result_to_string[res] << std::endl;
}

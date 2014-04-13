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

  SPF::Server srv("Example.com");

  SPF::Request req(srv);
  req.set_ipv4_str("108.83.36.113");
  req.set_helo_dom("digilicious.com");
  req.set_env_from("postmaster@digilicious.com");
  SPF::Response res(req);
  CHECK_EQ(res.result(), SPF::Result::PASS);
  std::cout << (res.header_comment() ? res.header_comment() : "") << std::endl;
  std::cout << (res.received_spf() ? res.received_spf() : "") << std::endl;

  std::cout << std::endl;

  SPF::Request req2(srv);
  req2.set_ipv4_str("10.1.1.1");
  req2.set_helo_dom("digilicious.com");
  req2.set_env_from("postmaster@digilicious.com");
  SPF::Response res2(req2);
  CHECK_EQ(res2.result(), SPF::Result::FAIL);
  std::cout << (res2.header_comment() ? res2.header_comment() : "") << std::endl;
  std::cout << (res2.received_spf() ? res2.received_spf() : "") << std::endl;
  std::cout << (res2.smtp_comment() ? res2.smtp_comment() : "") << std::endl;
}

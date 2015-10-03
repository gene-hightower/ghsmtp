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
  google::InitGoogleLogging(argv[0]);

  CHECK_EQ(sizeof(SPF::Server), sizeof(void*));
  CHECK_EQ(sizeof(SPF::Request), sizeof(void*));

  SPF::Server srv("Example.com");

  SPF::Request req(srv);
  req.set_ipv4_str("108.83.36.113");
  req.set_helo_dom("digilicious.com");
  req.set_env_from("postmaster@digilicious.com");
  SPF::Response res(req);
  CHECK_EQ(res.result(), SPF::Result::PASS);
  CHECK(0 == strcmp(res.header_comment(), "Example.com: domain of "
                                          "digilicious.com designates "
                                          "108.83.36.113 as permitted sender"));
  CHECK(0 == strcmp(res.received_spf(), "Received-SPF: pass (Example.com: "
                                        "domain of digilicious.com designates "
                                        "108.83.36.113 as permitted sender) "
                                        "client-ip=108.83.36.113; "
                                        "envelope-from=postmaster@digilicious."
                                        "com; helo=digilicious.com;"));
  SPF::Request req2(srv);
  req2.set_ipv4_str("10.1.1.1");
  req2.set_helo_dom("digilicious.com");
  req2.set_env_from("postmaster@digilicious.com");
  SPF::Response res2(req2);
  CHECK_EQ(res2.result(), SPF::Result::FAIL);
  CHECK(0 == strcmp(res2.header_comment(), "Example.com: domain of "
                                           "digilicious.com does not designate "
                                           "10.1.1.1 as permitted sender"));
  CHECK(0 == strcmp(res2.received_spf(), "Received-SPF: fail (Example.com: "
                                         "domain of digilicious.com does not "
                                         "designate 10.1.1.1 as permitted "
                                         "sender) client-ip=10.1.1.1; "
                                         "envelope-from=postmaster@digilicious."
                                         "com; helo=digilicious.com;"));
  CHECK(0 == strcmp(res2.smtp_comment(), "Please see "
                                         "http://www.openspf.org/"
                                         "Why?id=postmaster%40digilicious.com&"
                                         "ip=10.1.1.1&receiver=Example.com : "
                                         "Reason: mechanism"));
}

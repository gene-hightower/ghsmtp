#include "SPF.hpp"

#include <iostream>

int main(int argc, char const* argv[])
{
  CHECK_EQ(sizeof(SPF::Server), sizeof(void*));
  CHECK_EQ(sizeof(SPF::Request), sizeof(void*));

  SPF::Server const srv{"Example.com"};

  SPF::Request req{srv};
  req.set_ipv4_str("108.83.36.113");
  req.set_helo_dom("digilicious.com");
  req.set_env_from("postmaster@digilicious.com");
  SPF::Response const res{req};
  CHECK_EQ(res.result(), SPF::Result::PASS);
  CHECK(0
        == strcmp(res.header_comment(), "Example.com: domain of "
                                        "digilicious.com designates "
                                        "108.83.36.113 as permitted sender"));
  auto pass_new = "Received-SPF: pass (Example.com: "
                  "domain of digilicious.com designates "
                  "108.83.36.113 as permitted sender) "
                  "client-ip=108.83.36.113; "
                  "envelope-from=\"postmaster@digilicious."
                  "com\"; helo=digilicious.com;";
  auto pass_old = "Received-SPF: pass (Example.com: "
                  "domain of digilicious.com designates "
                  "108.83.36.113 as permitted sender) "
                  "client-ip=108.83.36.113; "
                  "envelope-from=postmaster@digilicious."
                  "com; helo=digilicious.com;";

  CHECK((0 == strcmp(res.received_spf(), pass_new))
        || (0 == strcmp(res.received_spf(), pass_old)));

  SPF::Request req2{srv};
  req2.set_ipv4_str("10.1.1.1");
  req2.set_helo_dom("digilicious.com");
  req2.set_env_from("postmaster@digilicious.com");
  SPF::Response const res2{req2};
  CHECK_EQ(res2.result(), SPF::Result::FAIL);
  CHECK(0
        == strcmp(res2.header_comment(), "Example.com: domain of "
                                         "digilicious.com does not designate "
                                         "10.1.1.1 as permitted sender"));

  auto fail_new = "Received-SPF: fail (Example.com: "
                  "domain of digilicious.com does not "
                  "designate 10.1.1.1 as permitted "
                  "sender) client-ip=10.1.1.1; "
                  "envelope-from=\"postmaster@digilicious."
                  "com\"; helo=digilicious.com;";
  auto fail_old = "Received-SPF: fail (Example.com: "
                  "domain of digilicious.com does not "
                  "designate 10.1.1.1 as permitted "
                  "sender) client-ip=10.1.1.1; "
                  "envelope-from=postmaster@digilicious."
                  "com; helo=digilicious.com;";

  CHECK((0 == strcmp(res2.received_spf(), fail_new))
        || (0 == strcmp(res2.received_spf(), fail_old)));

  CHECK(0
        == strcmp(res2.smtp_comment(), "Please see "
                                       "http://www.openspf.org/"
                                       "Why?id=postmaster%40digilicious.com&"
                                       "ip=10.1.1.1&receiver=Example.com : "
                                       "Reason: mechanism"));
}

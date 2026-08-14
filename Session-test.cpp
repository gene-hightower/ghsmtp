#include "Session.hpp"

#include "osutil.hpp"

#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std::string_literals;

struct Session_test {
  static void test()
  {
    std::cout << "sizeof(Session)          == " << sizeof(Session) << '\n';

    setenv("GHSMTP_SERVER_ID", "digilicious.com", 1);

    int fd_null = open("/dev/null", O_WRONLY);
    PCHECK(fd_null >= 0) << " can't open /dev/null";

    auto const config_path = osutil::get_config_dir();
    auto       read_hook   = []() { std::cout << "Session-test read_hook\n"; };
    Session    sess(config_path, read_hook, STDIN_FILENO, fd_null);

    auto sender{Domain{"example.er"}}; // Not a public suffix
    auto error_msg{std::string{}};
    CHECK(sess.verify_sender_domain_(sender, error_msg));

    // bogus
    CHECK(!sess.verify_sender_domain_(
        Domain("invalid-domain-has-only-one-label"), error_msg));

    // allow listed
    CHECK(sess.verify_sender_domain_(Domain("lots.of.labels.digilicious.com"),
                                     error_msg));
    CHECK(sess.verify_sender_domain_(Domain("allowlisted.digilicious.com"),
                                     error_msg));
    CHECK(sess.verify_sender_domain_(
        Domain("reg-domain-is-allowlisted.digilicious.com"), error_msg));

    // bounce address
    CHECK(sess.verify_sender_domain_(Domain(""), error_msg));

    CHECK(!sess.verify_sender_domain_(Domain("com"), error_msg));

    // IP address
    // auto error_msg{std::string{}};
    // CHECK(!sess.verify_ip_address_("blocklisted.digilicious.com"s));

    sess.ehlo("example.com");

    Session::parameters_t from_parameters;
    from_parameters["BODY"s]     = "8BITMIME"s;
    from_parameters["SIZE"s]     = "100"s;
    from_parameters["SMTPUTF8"s] = ""s;
    sess.mail_from(Mailbox("Postmaster", Domain("example.com")),
                   from_parameters);

    Session::parameters_t to_parameters;
    sess.rcpt_to(Mailbox("foo-bar", Domain("digilicious.com")), to_parameters);

    std::string_view data = "To: foo-bar@digilicious.com\r\n"
                            "From: Postsmaster@example.com\r\n"
                            "Subject: foo bar baz\r\n"
                            "\r\nSome text.\r\n";
    sess.data_start();
    sess.msg_write(data.data(), data.size());
    sess.data_done();
  }
};

int main(int argc, char* argv[]) { Session_test::test(); }

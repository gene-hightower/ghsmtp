#include "Session.hpp"

#include "osutil.hpp"

#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct Session_test {
  static void test()
  {
    std::cout << "sizeof(Session)       == " << sizeof(Session) << '\n';
    std::cout << "sizeof(sock_)         == " << sizeof(Session::sock_) << '\n';
    std::cout << "sizeof(client_)       == " << sizeof(Session::client_)
              << '\n';
    std::cout << "sizeof(reverse_path_) == " << sizeof(Session::reverse_path_)
              << '\n';
    std::cout << "sizeof(forward_path_) == " << sizeof(Session::forward_path_)
              << '\n';
    std::cout << "sizeof(binarymime_)   == " << sizeof(Session::binarymime_)
              << '\n';

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
        Domain("invalid-domain-has-only-one-lable"), error_msg));

    // allow listed
    CHECK(sess.verify_sender_domain_(Domain("lots.of.lables.digilicious.com"),
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
  }
};

int main(int argc, char* argv[]) { Session_test::test(); }

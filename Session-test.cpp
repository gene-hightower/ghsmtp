#include "Session.hpp"

#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct Session_test {
  static void test()
  {
    std::cout << "sizeof(Session) == " << sizeof(Session) << '\n';

    int fd_null = open("/dev/null", O_WRONLY);
    PCHECK(fd_null >= 0) << " can't open /dev/null";

    Session sess(STDIN_FILENO, fd_null, "example.com");

    LOG(ERROR) << "Expect: 3 invalid sender domains:";
    CHECK(!sess.verify_sender_domain_("com"));
    CHECK(!sess.verify_sender_domain_("zzux.com"));
    CHECK(!sess.verify_sender_domain_("blogspot.com.ar"));
  }
};

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Session_test::test();
}

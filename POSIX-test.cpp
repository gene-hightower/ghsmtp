#include "POSIX.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  POSIX::set_nonblocking(0);

  // Input /might/ be ready, so no CHECK().
  POSIX::input_ready(0, std::chrono::milliseconds(1));
  CHECK(POSIX::output_ready(1, std::chrono::milliseconds(1)));
}

#include "is_ascii.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  CHECK(is_ascii("Any ASCII string"));
  CHECK(!is_ascii("Any “non-ASCII” string"));
}

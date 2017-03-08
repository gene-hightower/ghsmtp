#include "CDB.hpp"

#include <glog/logging.h>

#include <iostream>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  CDB cdb2("two-level-tlds");

  CHECK(cdb2.lookup("0.bg"));
  CHECK(cdb2.lookup("zzux.com"));
  CHECK(!cdb2.lookup("This should not be found."));

  CDB cdb3("three-level-tlds");

  CHECK(cdb3.lookup("act.edu.au"));
  CHECK(cdb3.lookup("zen.co.uk"));
  CHECK(!cdb3.lookup("This should not be found."));
}

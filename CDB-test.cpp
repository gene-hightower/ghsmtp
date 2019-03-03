#include "CDB.hpp"

#include "osutil.hpp"

#include <glog/logging.h>

#include <iostream>

int main(int argc, char* argv[])
{
  auto const config_dir = osutil::get_config_dir();

  auto const no_database = config_dir / "no database";
  CDB        no_db{no_database.c_str()};
  CHECK(!no_db.lookup("foo"));

  auto const two_level_tlds = config_dir / "two-level-tlds";
  CDB        cdb2{two_level_tlds.c_str()};

  CHECK(cdb2.lookup("0.bg"));
  CHECK(cdb2.lookup("zzux.com"));
  CHECK(!cdb2.lookup("This should not be found."));

  auto const three_level_tlds = config_dir / "three-level-tlds";
  CDB        cdb3{three_level_tlds.c_str()};

  CHECK(cdb3.lookup("act.edu.au"));
  CHECK(cdb3.lookup("zen.co.uk"));
  CHECK(!cdb3.lookup("This should not be found."));

  CDB        accept_dom;
  auto const accept_dom_path = config_dir / "accept_domains";

  CHECK(accept_dom.open(accept_dom_path.c_str()));
  CHECK(accept_dom.lookup(osutil::get_hostname().c_str()));
}

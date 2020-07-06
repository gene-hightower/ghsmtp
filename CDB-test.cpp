#include "CDB.hpp"

#include "osutil.hpp"

#include <glog/logging.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  auto const config_dir = osutil::get_config_dir();

  auto const no_database = config_dir / "unable-to-open-database";
  CDB        no_db{no_database};
  CHECK(!no_db.contains("foo"));

  auto const two_level_tlds = config_dir / "two-level-tlds";
  CDB        cdb2{two_level_tlds};

  CHECK(cdb2.contains("0.bg"));
  CHECK(cdb2.contains("zzux.com"));
  auto const val = cdb2.find("zzux.com");
  CHECK(val);
  CHECK_EQ(*val, "1");
  CHECK(!cdb2.contains("This should not be found."));

  auto const three_level_tlds = config_dir / "three-level-tlds";
  CDB        cdb3{three_level_tlds};

  CHECK(cdb3.contains("act.edu.au"));
  CHECK(cdb3.contains("zen.co.uk"));
  CHECK(!cdb3.contains("This should not be found."));

  CDB        accept_dom;
  auto const accept_dom_path = config_dir / "accept_domains";

  CHECK(accept_dom.open(accept_dom_path.c_str()));

  // Ug, should not need c_str() here:
  std::ifstream in(accept_dom_path.c_str(), std::ios::in | std::ios::binary);

  if (!in.is_open())
    std::perror(
        ("error while opening file "s + accept_dom_path.string()).c_str());

  std::string line;
  getline(in, line);
  if (in.bad())
    perror(("error while reading file "s + accept_dom_path.string()).c_str());
  in.close();

  CHECK(accept_dom.contains(line));
}

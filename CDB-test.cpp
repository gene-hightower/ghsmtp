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
  CDB        no_db;
  CHECK(!no_db.open(no_database));
  CHECK(!no_db.contains("foo"));

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

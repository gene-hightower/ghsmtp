#include "osutil.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  auto const config_path = osutil::get_config_dir();
  auto const exe_path    = osutil::get_exe_path();
  auto const home_dir    = osutil::get_home_dir();
  auto const hostname    = osutil::get_hostname();

  fs::path argv0 = argv[0];
  CHECK_EQ(argv0.filename(), exe_path.filename());
}

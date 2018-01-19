#pragma once

#include <string>

#include "fs.hpp"

namespace osutil {
fs::path get_config_dir();
fs::path get_home_dir();
std::string get_hostname();
} // namespace osutil

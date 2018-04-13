#pragma once

#include <string>

#include "fs.hpp"

namespace osutil {
fs::path get_config_dir();
fs::path get_home_dir();
std::string get_hostname();
std::vector<fs::path> list_directory(fs::path const& path,
                                     std::string const& pattern);
} // namespace osutil

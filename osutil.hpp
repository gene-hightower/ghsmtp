#ifndef OSUTIL_DOT_HPP_INCLUDED
#define OSUTIL_DOT_HPP_INCLUDED

#include <string>
#include <vector>

#include "fs.hpp"

namespace osutil {
fs::path    get_config_dir();
fs::path    get_exe_path();
fs::path    get_home_dir();
std::string get_hostname();
uint16_t    get_port(char const* const service, char const* const proto);
std::vector<fs::path> list_directory(fs::path const&    path,
                                     std::string const& pattern);
} // namespace osutil

#endif // OSUTIL_DOT_HPP_INCLUDED

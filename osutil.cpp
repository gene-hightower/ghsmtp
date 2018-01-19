#include "osutil.hpp"

#include "fs.hpp"

#include <sys/utsname.h>
#include <unistd.h>

#include <glog/logging.h>

namespace osutil {

std::string get_hostname()
{
  utsname un;
  PCHECK(uname(&un) == 0);
  return std::string(un.nodename);
}

void set_home_dir()
{
  auto const exe{fs::path("/proc/self/exe")};
  CHECK(fs::exists(exe) && fs::is_symlink(exe))
      << "can't find myself: is this not a Linux kernel?";

  // The std::experimental::filesystem::read_symlink() as shipped with
  // GCC 7.2.1 20170915 included with Fedora 27 is unusable when lstat
  // returns st_size of zero, as happens with /proc/self/exe.

  // This problem has been corrected in later versions, but my little
  // loop should work on everything POSIX.

  auto p{std::string{64, '\0'}};
  for (;;) {
    auto const len{::readlink(exe.c_str(), p.data(), p.size())};
    PCHECK(len > 0) << "readlink";
    if (len < static_cast<ssize_t>(p.size()))
      break;
    CHECK_LT(p.size(), 4096) << "link too long";
    p.resize(p.size() * 2);
  }

  auto const path = fs::path(p).parent_path();

  // Maybe work from some installed location...

  // if (fs::is_directory(path) && (path.filename() == "bin")) {
  //   // if ends in /bin, switch to /share
  //   auto share = path;
  //   share.replace_filename("share");
  //   if (fs::exists(share) && fs::is_directory(share))
  //     path = share;
  // }

  current_path(path);
}

} // namespace osutil

#include "osutil.hpp"

#include "iobuffer.hpp"

#include <regex>

#include <boost/algorithm/string/classification.hpp>
// #include <boost/algorithm/string/split.hpp>

#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gflags/gflags.h>
namespace gflags {
}

DEFINE_string(config_dir, "", "path to support/config files");

#include <sys/utsname.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <glog/logging.h>

namespace osutil {

fs::path get_config_dir()
{
  if (!FLAGS_config_dir.empty()) {
    return FLAGS_config_dir;
  }
  else {
    return get_exe_path().parent_path();

    // Maybe work from some installed location...
    // if ends in /bin, switch to /share or /etc

    // auto path = get_exe_path().parent_path();
    // if (fs::is_directory(path) && (path.filename() == "bin")) {
    //   auto share = path;
    //   share.replace_filename("share");
    //   if (fs::exists(share) && fs::is_directory(share))
    //   path = share;
    // }
  }
}

fs::path get_exe_path()
{
  // The std::experimental::filesystem::read_symlink() as shipped with
  // GCC 7.2.1 20170915 included with Fedora 27 is unusable when lstat
  // returns st_size of zero, as happens with /proc/self/exe.

  // This problem has been corrected in later versions, but this code
  // should work on everything POSIX.

  auto constexpr exe = "/proc/self/exe";

  auto constexpr max_link = 4 * 1024;
  char buf[max_link];

  auto const len{::readlink(exe, buf, max_link)};

  PCHECK(len != -1) << "readlink";
  if (len == max_link) {
    LOG(FATAL) << exe << " link too long";
  }
  buf[len] = '\0';
  return fs::path(buf);
}

fs::path get_home_dir()
{
  auto const homedir_ev{getenv("HOME")};
  if (homedir_ev) {
    return homedir_ev;
  }
  else {
    errno = 0; // See GETPWNAM(3)
    passwd* pw;
    PCHECK(pw = getpwuid(getuid()));
    return pw->pw_dir;
  }
}

std::string get_hostname()
{
  utsname un;
  PCHECK(uname(&un) == 0);

  auto node = std::string(un.nodename);

  // auto labels{std::vector<std::string>{}};
  // boost::algorithm::split(labels, node,
  //                         boost::algorithm::is_any_of("."));
  // if (labels.size() < 2) {
  //   node += ".digilicious.com";
  // }

  return node;
}

uint16_t get_port(char const* const service, char const* const proto)
{
  char*      ep = nullptr;
  auto const service_no{strtoul(service, &ep, 10)};
  if (ep && (*ep == '\0')) {
    CHECK_LE(service_no, std::numeric_limits<uint16_t>::max());
    return static_cast<uint16_t>(service_no);
  }

  iobuffer<char> str_buf{1024}; // suggested by getservbyname_r(3)

  auto     result_buf{servent{}};
  servent* result_ptr = nullptr;
  while (getservbyname_r(service, proto, &result_buf, str_buf.data(),
                         str_buf.size(), &result_ptr)
         == ERANGE) {
    CHECK_LT(str_buf.size(), 64 * 1024); // ridiculous
    str_buf.resize(str_buf.size() * 2);
  }
  if (result_ptr == nullptr) {
    LOG(FATAL) << "service " << service << " unknown";
  }
  return ntohs(result_buf.s_port);
}

std::vector<fs::path> list_directory(
    fs::path const& path,
    // pattern should be std::string_view see p0506r0:
    // <http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/p0506r0.pdf>
    // maybe C++20?
    std::string const& pattern)
{
  std::vector<fs::path> ret;

  auto const traits = std::regex_constants::ECMAScript
#if defined(__APPLE__) || defined(_WIN32)
                      | std::regex_constants::icase
#endif
      ;

  std::regex const pattern_regex(pattern, traits);

  auto const di = fs::directory_iterator(path);
  for (auto const& it : di) {
    auto const  it_filename = it.path().filename().string();
    std::smatch matches;
    if (std::regex_match(it_filename, matches, pattern_regex)) {
      ret.push_back(it.path());
    }
  }

  return ret;
}

} // namespace osutil

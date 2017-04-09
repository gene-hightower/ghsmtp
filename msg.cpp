#include <glog/logging.h>

#include <experimental/string_view>
using std::experimental::string_view;

#define BOOST_FILESYSTEM_NO_DEPRECATED
#include <boost/filesystem.hpp>

#include <boost/iostreams/device/mapped_file.hpp>

#include <iostream>

void proc_msg(string_view msg)
{
  std::cout << msg.size() << '\n';
}

int main(int argc, char const* argv[])
{
  for (auto i=1; i<argc; ++i) {
    boost::filesystem::path name(argv[i]);
    boost::iostreams::mapped_file_source f(name);  
    proc_msg(string_view(f.data(), f.size()));
  }
}

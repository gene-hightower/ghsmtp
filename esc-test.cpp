#include "esc.hpp"
#include "fs.hpp"
#include "imemstream.hpp"

#include <iostream>
#include <string>

#include <glog/logging.h>

#include <boost/iostreams/device/mapped_file.hpp>

int main(int argc, char* argv[])
{
  auto const s0 = "\a\xa0\b\t\n\v\f\r\\";
  CHECK_EQ(esc(s0), "\\a\\xa0\\b\\t\\n\\v\\f\\r\\\\");

  auto const s1 = "no characters to escape";
  CHECK_EQ(esc(s1), s1);

  for (auto arg = 1; arg < argc; ++arg) {
    fs::path const path{argv[arg]};

    auto const body_sz{fs::file_size(path)};
    if (!body_sz)
      continue;

    boost::iostreams::mapped_file_source file_source{};
    file_source.open(path);

    imemstream isfile{file_source.data(), file_source.size()};
    std::string line;
    while (std::getline(isfile, line)) {
      if (!isfile.eof())
        line += '\n'; // since getline strips the newline
      std::cout << esc(line, esc_line_option::multi) << '\n';
    }
  }
}

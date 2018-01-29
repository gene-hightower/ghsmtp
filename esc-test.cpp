#include "esc.hpp"
#include "fs.hpp"
#include "imemstream.hpp"

#include <iostream>
#include <string>

#include <glog/logging.h>

#include <boost/iostreams/device/mapped_file.hpp>

using namespace std::string_literals;

int main(int argc, char* argv[])
{
  std::string s0;
  s0 += '\a';
  s0 += '\xa0';
  s0 += '\b';
  s0 += '\t';
  s0 += '\n';
  s0 += '\v';
  s0 += '\f';
  s0 += '\r';
  s0 += '\\';
  auto escaped0 = esc(s0);
  CHECK_EQ(escaped0, "\\a\\xa0\\b\\t\\n\\v\\f\\r\\\\"s);

  auto s1 = "not escaped at all"s;
  CHECK_EQ(esc(s1), s1);

  for (auto arg = 1; arg < argc; ++arg) {
    auto const path{fs::path{argv[arg]}};

    auto const body_sz{fs::file_size(path)};
    if (!body_sz)
      continue;

    auto file_source{boost::iostreams::mapped_file_source{}};
    file_source.open(path);

    auto isfile{imemstream{file_source.data(), file_source.size()}};
    auto line{std::string{}};
    while (std::getline(isfile, line)) {
      if (!isfile.eof())
        line += '\n'; // since getline strips the newline
      auto const escaped{esc(line, esc_line_option::multi)};
      std::cout << escaped << '\n';
    }
  }
}

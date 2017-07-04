#include "Now.hpp"
#include "Pill.hpp"

#include <sys/utsname.h>

#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <glog/logging.h>

#include <experimental/string_view>

using std::experimental::string_view;
using namespace std::string_literals;

struct Eml {
  std::vector<std::pair<std::string, std::string>> hdrs;
};

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  Eml eml;

  Now date;
  eml.hdrs.push_back(std::make_pair("Date"s, date.string()));

  eml.hdrs.push_back(
      std::make_pair("From"s, "Gene Hightower <基因@digilicious.com>"s));
  eml.hdrs.push_back(
      std::make_pair("To"s, "Gene Hightower <基因@digilicious.com>"s));
  eml.hdrs.push_back(std::make_pair("Subject"s, "This is a test email…"s));
  eml.hdrs.push_back(std::make_pair("Keywords"s, "everyone loves π, 🔑, 🌀"s));

  utsname un;
  PCHECK(uname(&un) == 0);
  Pill red, blue;
  std::stringstream mid_str;
  mid_str << '<' << date.sec() << '.' << red << '.' << blue << '@'
          << un.nodename << '>';
  eml.hdrs.push_back(std::make_pair("Message-ID"s, mid_str.str()));

  for (auto const& h : eml.hdrs) {
    std::cout << h.first << ": " << h.second << "\r\n";
  }

  std::cout << "\r\n";

  std::ifstream body("body.txt");
  std::string line;
  while (std::getline(body, line)) {
    std::cout << line;
    if (line.back() != '\r')
      std::cout << '\r';
    std::cout << '\n';
  }
}

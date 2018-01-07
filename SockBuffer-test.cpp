#include "SockBuffer.hpp"

#include <fcntl.h>

#include <fstream>
#include <iostream>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  constexpr char infile[]{"input.txt"};

  int fd_in;
  PCHECK((fd_in = open(infile, O_RDONLY)) != -1);

  constexpr char tmplt[]{"/tmp/SockBuffert-XXXXXX"};
  char outfile[sizeof(tmplt)];
  strcpy(outfile, tmplt);

  int fd_out;
  PCHECK((fd_out = mkstemp(outfile)) != -1);

  auto read_hook = []() { std::cout << "read_hook\n"; };

  boost::iostreams::stream<SockBuffer> iostream{fd_in,
                                                fd_out,
                                                read_hook,
                                                std::chrono::seconds(10),
                                                std::chrono::seconds(10),
                                                std::chrono::seconds(1)};

  std::string line;
  while (std::getline(iostream, line)) {
    iostream << line << '\n';
  }
  iostream << std::flush;

  std::string diff_cmd = "diff ";
  diff_cmd += infile;
  diff_cmd += " ";
  diff_cmd += outfile;
  CHECK_EQ(system(diff_cmd.c_str()), 0);

  PCHECK(!unlink(outfile)) << "unlink failed for " << outfile;

  std::cout << "sizeof(SockBuffer) == " << sizeof(SockBuffer) << '\n'
            << std::flush;
}

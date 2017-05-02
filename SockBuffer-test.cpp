#include "SockBuffer.hpp"

#include <fcntl.h>

#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  constexpr char infile[]{"input.txt"};

  int fd_in;
  PCHECK((fd_in = open(infile, O_RDONLY)) != -1);

  constexpr char tmplt[]{"/tmp/SockBuffert-XXXXXX"};
  char outfile[sizeof(tmplt)];
  strcpy(outfile, tmplt);

  int fd_out;
  PCHECK((fd_out = mkstemp(outfile)) != -1);

  boost::iostreams::stream<SockBuffer> iostream{SockBuffer(fd_in, fd_out)};

  std::string line;
  while (std::getline(iostream, line)) {
    iostream << line << std::endl;
  }

  std::string diff_cmd = "diff ";
  diff_cmd += infile;
  diff_cmd += " ";
  diff_cmd += outfile;
  CHECK_EQ(system(diff_cmd.c_str()), 0);

  PCHECK(!unlink(outfile)) << "unlink failed for " << outfile;

  std::cout << "sizeof(SockBuffer) == " << sizeof(SockBuffer) << std::endl;
}

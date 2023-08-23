#include "SockBuffer.hpp"

#include <fcntl.h>

#include <fstream>
#include <iostream>

#include <fmt/format.h>

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  constexpr auto infile = "body.txt";

  int fd_in = open(infile, O_RDONLY);
  PCHECK(fd_in != -1) << "Can't open file " << infile;

  char outfile[] = "/tmp/SockBuffer-test-XXXXXX";

  int fd_out = mkstemp(outfile);
  PCHECK(fd_out != -1);

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
  iostream.clear(); // unset eof bit, if set will short-circut flush
  iostream << std::flush;

  auto const diff_cmd{fmt::format("diff {} {}", infile, outfile)};
  CHECK_EQ(system(diff_cmd.c_str()), 0);

  PCHECK(!unlink(outfile)) << "unlink failed for " << outfile;

  std::cout << "sizeof(SockBuffer) == " << sizeof(SockBuffer) << '\n';
}

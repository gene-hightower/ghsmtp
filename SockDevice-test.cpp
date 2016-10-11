/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "SockDevice.hpp"

#include <glog/logging.h>

#include <fcntl.h>

#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
  google::InitGoogleLogging(argv[0]);

  constexpr char infile[]{"input.txt"};

  int fd_in;
  PCHECK((fd_in = open(infile, O_RDONLY)) != -1);

  constexpr char tmplt[]{"/tmp/SockDevice-XXXXXX"};
  char outfile[sizeof(tmplt)];
  strcpy(outfile, tmplt);

  int fd_out;
  PCHECK((fd_out = mkstemp(outfile)) != -1);

  boost::iostreams::stream<SockDevice> iostream{SockDevice(fd_in, fd_out)};

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

  std::cout << "sizeof(SockDevice) == " << sizeof(SockDevice) << '\n';
}

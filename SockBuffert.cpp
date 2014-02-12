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

#include "SockBuffer.hpp"

#include "Logging.hpp"

#include <fcntl.h>

#include <fstream>
#include <iostream>

int main(int argc, char* argv[])
{
  Logging::init(argv[0]);

  // std::filebuf buf; buf.open("/dev/stdin", std::ios::in);

  int fd;
  PCHECK((fd = open("input.txt", O_RDONLY)) != -1);

  boost::iostreams::stream<SockBuffer> iostream{ SockBuffer(fd, STDOUT_FILENO) };

  std::string line;
  while (std::getline(iostream, line)) {
    std::cout << line << std::endl;
  }

  std::cout << "sizeof(SockBuffer) == " << sizeof(SockBuffer)
            << std::endl;
}

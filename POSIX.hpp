/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

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

#ifndef POSIX_DOT_HPP
#define POSIX_DOT_HPP

#include <chrono>
#include <ios>

namespace POSIX {

void set_nonblocking(int fd);

bool input_ready(int fd_in, std::chrono::milliseconds wait);
bool output_ready(int fd_out, std::chrono::milliseconds wait);

std::streamsize read(int fd_in, char* s, std::streamsize n,
                     std::chrono::milliseconds timeout, bool& t_o);
std::streamsize write(int fd_out, const char* s, std::streamsize n,
                      std::chrono::milliseconds timeout, bool& t_o);
}

#endif // POSIX_DOT_HPP

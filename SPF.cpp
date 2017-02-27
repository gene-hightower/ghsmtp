/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#include "SPF.hpp"

namespace SPF {

std::ostream& operator<<(std::ostream& os, Result result)
{
  switch (result) {
  case Result::INVALID:
    return os << "INVALID";
  case Result::NEUTRAL:
    return os << "NEUTRAL";
  case Result::PASS:
    return os << "PASS";
  case Result::FAIL:
    return os << "FAIL";
  case Result::SOFTFAIL:
    return os << "SOFTFAIL";
  case Result::NONE:
    return os << "NONE";
  case Result::TEMPERROR:
    return os << "TEMPERROR";
  case Result::PERMERROR:
    return os << "PERMERROR";
  }
  return os << "Unknown";
};

// We map libspf2's levels of error, warning, info and debug to our
// own fatal, error, warning and info log levels.

static void log_error(const char* file, int line, char const* errmsg)
#ifdef __clang__
    __attribute__((noreturn))
#endif
{
  LOG(FATAL) << file << ":" << line << " " << errmsg;
}
static void log_warning(const char* file, int line, char const* errmsg)
{
  LOG(ERROR) << file << ":" << line << " " << errmsg;
}
static void log_info(const char* file, int line, char const* errmsg)
{
  LOG(WARNING) << file << ":" << line << " " << errmsg;
}

struct Init {
  Init()
  {
    SPF_error_handler = log_error;
    SPF_warning_handler = log_warning;
    SPF_info_handler = log_info;
    SPF_debug_handler = nullptr;
  }
};

static Init init;
}

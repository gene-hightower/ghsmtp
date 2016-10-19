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

#include "SPF.hpp"

namespace SPF {

std::ostream& operator<<(std::ostream& os, Result result)
{
  char const* msg = "Unknown";
  switch (result) {
  case Result::INVALID:
    msg = "INVALID";
    break;
  case Result::NEUTRAL:
    msg = "NEUTRAL";
    break;
  case Result::PASS:
    msg = "PASS";
    break;
  case Result::FAIL:
    msg = "FAIL";
    break;
  case Result::SOFTFAIL:
    msg = "SOFTFAIL";
    break;
  case Result::NONE:
    msg = "NONE";
    break;
  case Result::TEMPERROR:
    msg = "TEMPERROR";
    break;
  case Result::PERMERROR:
    msg = "PERMERROR";
    break;
  }
  return os << msg;
};

// We map libspf2's levels of error, warning, info and debug to our
// own fatal, error, warning and info log levels.

static void log_error(const char* file, int line, char const* errmsg)
#ifdef __clang__
__attribute__((noreturn))
#endif
{
  LOG(FATAL) << errmsg;
}
static void log_warning(const char* file, int line, char const* errmsg)
{
  LOG(ERROR) << errmsg;
}
static void log_info(const char* file, int line, char const* errmsg)
{
  LOG(WARNING) << errmsg;
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

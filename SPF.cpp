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

std::unordered_map<Result, char const*> result_to_string{
  { Result::INVALID, "INVALID" },
  { Result::NEUTRAL, "NEUTRAL" },
  { Result::PASS, "PASS" },
  { Result::FAIL, "FAIL" },
  { Result::SOFTFAIL, "SOFTFAIL" },
  { Result::NONE, "NONE" },
  { Result::TEMPERROR, "TEMPERROR" },
  { Result::PERMERROR, "PERMERROR" },
};

// We map libspf2's levels of error, warning, info and debug to
// Google's fatal, error, warning and info.

static void glog_error(const char* file, int line, char const* errmsg)
    __attribute__((noreturn)); // This just is for GCC 4.8.2 which
                               // can't take the attribute on the
                               // function definition.

static void glog_error(const char* file, int line, char const* errmsg)
{
  google::LogMessageFatal(file, line).stream() << errmsg;
}
static void glog_warning(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line, google::GLOG_ERROR).stream() << errmsg;
}
static void glog_info(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line, google::GLOG_WARNING).stream() << errmsg;
}
static void glog_debug(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line).stream() << errmsg;
}

struct Init {
  Init()
  {
    SPF_error_handler = glog_error;
    SPF_warning_handler = glog_warning;
    SPF_info_handler = glog_info;
    SPF_debug_handler = glog_debug;
  }
};

static Init init;
}

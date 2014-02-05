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

#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <glog/logging.h>

namespace Logging {

inline void init(char const* program_name)
{
  google::InitGoogleLogging(program_name);
  google::InstallFailureSignalHandler();
  fLI::FLAGS_stderrthreshold = 4; // No stderr for log messages.
}
}

#endif

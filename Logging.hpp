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

// This is original code based on the Google "glog" code.  To the
// extent that it includes anything that Google holds copyright to:
//
// Copyright (c) 1999, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#include <sys/types.h>

#ifdef WIN32
// MinGW 4.8.1 needs off64_t defined before including <fcntl.h> when
// using -std=c++1y:
using off64_t = _off64_t;
#endif

#include <fcntl.h>

#ifdef _POSIX_SOURCE
#include <unistd.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#endif

#ifdef WIN32
#include <windows.h>
#include <winsock.h> // for GetComputerNameA
#include <io.h>
#include <process.h> // for _getpid()

#undef ERROR

#endif // WIN32

#include <boost/lexical_cast.hpp>

namespace Logging {

extern char const* program_name;
extern int log_fd;

// Use localtime_r() if we have one, otherwise fall back to
// localtime().  In the context of logging, this should be just fine
// if we're always calling localtime with a time_t representing, more
// or less, "now."

#undef localtime_r // defined by win-builds / gcc 4.8.2

namespace query {
char localtime_r(...);

struct has_localtime_r {
  enum {
    value = sizeof localtime_r(std::declval<std::time_t*>(),
                               std::declval<std::tm*>()) == sizeof(std::tm*)
  };
};

template <bool available>
struct safest_localtime {
  static std::tm* call(std::time_t const* t, std::tm* r)
  {
    return localtime_r(t, r);
  }
};

template <>
struct safest_localtime<false> {
  static std::tm* call(std::time_t const* t, std::tm* r)
  {
    return std::localtime(t);
  }
};
}

inline std::tm* localtime(std::time_t const* t, std::tm* r)
{
  return query::safest_localtime<query::has_localtime_r::value>().call(t, r);
}

inline std::string get_host_name()
{
#ifdef WIN32
  char buf[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD len = sizeof(buf);
  if (GetComputerNameA(buf, &len)) {
    return std::string(buf);
  }
#endif

#ifdef _POSIX_SOURCE
  struct utsname un;
  if (0 == uname(&un)) {
    return std::string(un.nodename);
  }
#endif

  return std::string("unknown");
}

inline std::string base_name(std::string const& name)
{
  size_t sl = name.find_last_of('/');
  if (sl == std::string::npos)
    return name;
  return std::string(name, sl + 1);
}

inline void init(char const* prgrm_nm)
{
  if (nullptr != program_name)
    return; // Call this function only once.

  program_name = prgrm_nm;

  std::string logdir;

  char const* ev = std::getenv("GOOGLE_LOG_DIR");
  if (ev) {
    logdir = ev;
  } else {
    ev = std::getenv("LOG_DIR");
    if (ev) {
      logdir = ev;
    } else {
      logdir = "/tmp";
    }
  }

  auto t = time(nullptr);

  std::tm tm_local;
  std::tm* tm_ptr = localtime(&t, &tm_local);

  char tm_str[16];
  constexpr char const* tm_fmt = "%Y%m%d-%H%M%S";
  size_t s = strftime(tm_str, sizeof(tm_str), tm_fmt, tm_ptr);
  assert(s == sizeof(tm_str) - 1);

#ifdef WIN32
  char const* user = getenv("USERNAME");
#else
  char const* user = getenv("USER");
#endif
  if (nullptr == user) {
    user = "";
  }

  std::string filename = logdir + "/" + base_name(program_name) + "." +
                         get_host_name() + "." + user + ".log." + tm_str;

  filename += "." + boost::lexical_cast<std::string>(getpid());

  log_fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0664);
  if (log_fd < 0) {
    std::cerr << "open(\"" << filename << "\") failed!\n";
    log_fd = STDERR_FILENO;
  }

  constexpr char const header[] =
      "Log line format: [IWEF] yyyy-mm-dd hh:mm:ss.uuuuuu zzzzz "
      "threadid file:line] msg\n";

  s = write(log_fd, header, sizeof(header) - 1);
  assert(s == sizeof(header) - 1);
}

// This class is used to explicitly ignore values in the conditional
// logging macros.  This avoids compiler warnings like "value computed
// is not used" and "statement has no effect".

class MessageVoidify {
public:
  MessageVoidify()
  {
  }
  // This has to be an operator with a precedence lower than << but
  // higher than ?:
  void operator&(std::ostream&)
  {
  }
};

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define BRANCH_NOT_TAKEN(x) (unlikely(x))

enum class Severity : uint8_t {
  INFO,
  WARNING,
  ERROR,
  FATAL,
};

class Message {
public:
  Message(char const* file, int line) : Message(file, line, Severity::INFO)
  {
  }
  Message(char const* file, int line, Severity severity) : severity_(severity)
  {
    switch (severity_) {
    case Severity::INFO:
      msg_ << "I ";
      break;
    case Severity::WARNING:
      msg_ << "W ";
      break;
    case Severity::ERROR:
      msg_ << "E ";
      break;
    case Severity::FATAL:
      msg_ << "F ";
      break;
    }

    auto now = std::chrono::high_resolution_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto whole_second = std::chrono::system_clock::from_time_t(t);

    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now - whole_second).count();

    std::tm tm_local;
    std::tm* tm_ptr = localtime(&t, &tm_local);

    char tm_str[20];
    constexpr char const* tm_fmt = "%Y-%m-%d %H:%M:%S";
    size_t s = strftime(tm_str, sizeof(tm_str), tm_fmt, tm_ptr);
    assert(s == sizeof(tm_str) - 1);

    // The strftime() call on win-builds calls the MS version that,
    // for %z will: "Either the time-zone name or time zone
    // abbreviation, depending on registry settings; no characters if
    // time zone is unknown"

    char const* tm_str_z = " "; // default
    constexpr char const* tm_fmt_z = " %z ";
    char tm_str_bfr[8];
    s = strftime(tm_str_bfr, sizeof(tm_str_bfr), tm_fmt_z, tm_ptr);

    // If we have a version of strftime that gives us the +hhmm or
    // -hhmm numeric timezone, we use it.  Otherwise we default to a
    // single space from the initialization above.

    if (s == sizeof(tm_str_bfr) - 1) {
      tm_str_z = tm_str_bfr;
    }

    msg_ << tm_str << "." << std::setfill('0') << std::setw(6) << us << tm_str_z
         << boost::lexical_cast<std::string>(getpid()) << " " << file << ":"
         << static_cast<unsigned>(line) << "] ";
  }

  virtual ~Message()
  {
    msg_ << std::endl;
    std::string msg_str = msg_.str();
    size_t msg_len = strlen(msg_.str().c_str());
    size_t s = write(log_fd, msg_str.c_str(), msg_len);
    assert(s == msg_len);
    if (Severity::FATAL == severity_) {
      abort();
    }
  }

  std::ostream& stream()
  {
    return msg_;
  }

private:
  Severity severity_;
  std::ostringstream msg_;
};

class ErrnoMessage : public Message {
public:
  ErrnoMessage(char const* file, int line, Severity severity)
    : Message(file, line, severity)
  {
  }

  ~ErrnoMessage() override
  {
    stream() << ": " << std::strerror(errno) << " ["
             << static_cast<unsigned>(errno) << "]";
  }
};
}

#define LOG_INFO Logging::Message(__FILE__, __LINE__)
#define LOG_WARNING                                                            \
  Logging::Message(__FILE__, __LINE__, Logging::Severity::WARNING)
#define LOG_ERROR Logging::Message(__FILE__, __LINE__, Logging::Severity::ERROR)
#define LOG_FATAL Logging::Message(__FILE__, __LINE__, Logging::Severity::FATAL)

#define PLOG_INFO Logging::ErrnoMessage(__FILE__, __LINE__)
#define PLOG_WARNING                                                           \
  Logging::ErrnoMessage(__FILE__, __LINE__, Logging::Severity::WARNING)
#define PLOG_ERROR                                                             \
  Logging::ErrnoMessage(__FILE__, __LINE__, Logging::Severity::ERROR)
#define PLOG_FATAL                                                             \
  Logging::ErrnoMessage(__FILE__, __LINE__, Logging::Severity::FATAL)

#define LOG(severity) LOG_##severity.stream()
#define PLOG(severity) PLOG_##severity.stream()

#define LOG_IF(severity, condition)                                            \
  !(condition) ? (void)0 : Logging::MessageVoidify() & LOG(severity)
#define PLOG_IF(severity, condition)                                           \
  !(condition) ? (void)0 : Logging::MessageVoidify() & PLOG(severity)

#define CHECK(condition)                                                       \
  LOG_IF(FATAL, BRANCH_NOT_TAKEN(!(condition)))                                \
      << "Check failed: " #condition " "
#define PCHECK(condition)                                                      \
  PLOG_IF(FATAL, BRANCH_NOT_TAKEN(!(condition)))                               \
      << "Check failed: " #condition " "

#define CHECK_EQ(val1, val2) CHECK((val1) == (val2))
#define CHECK_NE(val1, val2) CHECK((val1) != (val2))

#define CHECK_NOTNULL(val)                                                     \
  CheckNotNull(__FILE__, __LINE__, "'" #val "' Must not be nullptr", (val))

template <typename T>
T* CheckNotNull(char const* file, int line, char const* names, T* t)
{
  if (t == nullptr) {
    Logging::Message(file, line, Logging::Severity::FATAL).stream() << names;
  }
  return t;
}

#endif

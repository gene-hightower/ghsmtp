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

#ifndef MESSAGE_DOT_HPP
#define MESSAGE_DOT_HPP

#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

#include <pwd.h>
#include <sys/types.h>

#include "Now.hpp"
#include "Pill.hpp"

class Message {
public:
  Message() = default;
  void set_domain(std::string const& fqdn)
  {
    if (fqdn.empty())
      return;

    std::string maildir;

    char const* ev = getenv("MAILDIR");
    if (ev) {
      maildir = ev;
    }
    else {
      ev = getenv("HOME");
      if (ev) {
        CHECK(strcmp(ev, "/root")) << "should not run as root";
        maildir = ev;
      }
      else {
        errno = 0; // See GETPWNAM(3)
        passwd* pw;
        PCHECK(pw = getpwuid(getuid()));
        maildir = pw->pw_dir;
      }
      maildir += "/Maildir";
    }

    // Unique name, see: <http://cr.yp.to/proto/maildir.html>
    std::ostringstream uniq;
    uniq << then_.sec() << "."
         << "R" << s_ << "." << fqdn;

    tmpfn_ = maildir + "/tmp/" + uniq.str();
    newfn_ = maildir + "/new/" + uniq.str();

    // open
    ofs_.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    ofs_.open(tmpfn_.c_str());
  }
  Pill const& id() const { return s_; }
  Now const& when() const { return then_; }
  std::ostream& out() { return ofs_; }
  void save()
  {
    ofs_.close();
    PCHECK(rename(tmpfn_.c_str(), newfn_.c_str()) == 0);
  }
  void trash()
  {
    ofs_.close();
    PCHECK(remove(tmpfn_.c_str()) == 0);
  }

private:
  Pill s_;
  Now then_;

  std::ofstream ofs_;

  std::string tmpfn_;
  std::string newfn_;
};

#endif // MESSAGE_DOT_HPP

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

#ifndef MESSAGE_DOT_HPP
#define MESSAGE_DOT_HPP

#include <cstdlib>
#include <fstream>
#include <sstream>

#include <boost/filesystem.hpp>

#include <pwd.h>
#include <sys/types.h>

#include "Now.hpp"
#include "Pill.hpp"

class Message {
public:
  Message() = default;

  enum class SpamStatus : bool { ham, spam };

  void open(std::string const& fqdn, SpamStatus spam)
  {
    if (fqdn.empty())
      return;

    boost::filesystem::path maildir;

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
      maildir /= "Maildir";
    }

    if (spam == SpamStatus::spam) {
      maildir /= ".Junk";
    }

    // Unique name, see: <http://cr.yp.to/proto/maildir.html>
    std::ostringstream uniq;
    uniq << then_.sec() << "."
         << "R" << s_ << "." << fqdn;

    tmpfn_ = maildir;
    newfn_ = maildir;

    tmpfn_ /= "tmp";
    newfn_ /= "new";

    // mkdirs for tmpfn_ and newfn_
    boost::system::error_code ec;
    create_directories(tmpfn_, ec);
    create_directories(newfn_, ec);

    tmpfn_ /= uniq.str();
    newfn_ /= uniq.str();

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

  boost::filesystem::path tmpfn_;
  boost::filesystem::path newfn_;
};

#endif // MESSAGE_DOT_HPP

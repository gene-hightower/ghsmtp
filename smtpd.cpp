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

// Experimental untested version -- don't run this version!

#include <fstream>
#include <iomanip>
#include <regex>
#include <string>
#include <vector>

#include <signal.h>

#include "Session.hpp"

inline bool eat(std::istream& is, const char* str)
{
  while (*str && is.good()) {
    char ch;
    is.get(ch);
    if (toupper(ch) != *str++)
      return false;
  }
  return true;
}

void timeout(int signum)
{
  const char errmsg[] = "451 timeout\r\n";
  write(1, errmsg, sizeof errmsg - 1);
  exit(1);
}

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);

  google::InitGoogleLogging(argv[0]);

  // Set timeout signal handler.
  struct sigaction sact;
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);

  std::regex adrx("\\s*<(.+)@(.+)>");

  alarm(5 * 60); // Initial timeout set for command loop.

  Session session;
  session.greeting();

  while (!session.in().eof()) {
    std::string cmd;

    while (session.in().good()) {
      char ch;
      session.in().get(ch);
      if (isspace(ch))
        break;
      cmd += toupper(ch);
    }

    if ("HELO" == cmd) {
      std::string client_identity;
      std::getline(session.in(), client_identity, '\r');
      eat(session.in(), "\n");
      session.helo(client_identity);
      continue;
    }

    if ("EHLO" == cmd) {
      std::string client_identity;
      std::getline(session.in(), client_identity, '\r');
      eat(session.in(), "\n");
      session.ehlo(client_identity);
      continue;
    }

    if (("MAIL" == cmd) && eat(session.in(), "FROM:")) {
      std::string reverse_path;
      std::getline(session.in(), reverse_path, '\r');
      eat(session.in(), "\n");

      // parse the "from" address
      std::cmatch matches;

      if (std::regex_match(reverse_path.c_str(), matches, adrx)) {
        std::string local(matches[1].first, matches[1].second);
        std::string dom(matches[2].first, matches[2].second);

        session.mail_from(Mailbox(local, dom),
                          std::unordered_map<std::string, std::string>());
      }
      continue;
    }

    if (("RCPT" == cmd) && eat(session.in(), "TO:")) {
      std::string to;
      std::getline(session.in(), to, '\r');
      eat(session.in(), "\n");

      // parse the "to" address
      std::cmatch matches;

      if (std::regex_match(to.c_str(), matches, adrx)) {
        std::string local(matches[1].first, matches[1].second);
        std::string dom(matches[2].first, matches[2].second);

        session.rcpt_to(Mailbox(local, dom),
                        std::unordered_map<std::string, std::string>());
      }
      continue;
    }

    // All the commands that follow ignore any additional input, so we
    // eat the rest of the line including the \r\n.
    std::string ignore;
    std::getline(session.in(), ignore);

    if ("DATA" == cmd) {
      alarm(10 * 60); // Up the timeout for the DATA transfer.
      session.data();
      alarm(5 * 60); // Set the timeout back down for the
                     // command loop.
      continue;
    }

    if ("RSET" == cmd) {
      session.rset();
      continue;
    }

    if ("QUIT" == cmd) {
      session.quit();
      return 0;
    }

    if ("VRFY" == cmd) {
      session.vrfy();
      continue;
    }

    if ("NOOP" == cmd) {
      session.noop();
      continue;
    }

    if ("HELP" == cmd) {
      session.help();
      continue;
    }

    if ("STARTTLS" == cmd) {
      session.starttls();
      continue;
    }

    session.error("unrecognized command");
  }
}

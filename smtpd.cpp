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

// Experimental version with no bison -- don't run this version!

#include <fstream>
#include <iomanip>

#include <string>
#include <vector>

#include <signal.h>

#include "Session.hpp"

#include <boost/regex.hpp>

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

  Logging::init(argv[0]);

  // Set timeout signal handler.
  struct sigaction sact;
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, nullptr) == 0);

  boost::regex adrx("\\s*<(.+)@(.+)>");

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
      boost::cmatch matches;

      if (boost::regex_match(reverse_path.c_str(), matches, adrx)) {
        std::string local(matches[1].first, matches[1].second);
        std::string dom(matches[2].first, matches[2].second);

        Mailbox rp(local, dom);
        session.mail_from(rp, std::unordered_map<std::string, std::string>());
      }
      continue;
    }

    if (("RCPT" == cmd) && eat(session.in(), "TO:")) {
      std::string to;
      std::getline(session.in(), to, '\r');
      eat(session.in(), "\n");

      // parse the "to" address
      boost::cmatch matches;

      if (boost::regex_match(to.c_str(), matches, adrx)) {
        std::string local(matches[1].first, matches[1].second);
        std::string dom(matches[2].first, matches[2].second);

        Mailbox rto(local, dom);
        session.rcpt_to(rto, std::unordered_map<std::string, std::string>());
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

    session.error("unrecognized command");
  }
}

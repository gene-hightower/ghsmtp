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

// Experiments with boost::asio -- don't run this version!

#include <fstream>
#include <iomanip>

#include <string>
#include <vector>

#include <pwd.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/utsname.h>

#include <glog/logging.h>

#define BOOST_ASIO_DISABLE_EPOLL
#include <boost/asio.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

/////////////////////////////////////////////////////////////////////////////

char us_net_addr[INET6_ADDRSTRLEN];
char them_net_addr[INET6_ADDRSTRLEN];

std::string fqdn;
std::string client_identity;
std::string reverse_path;
std::vector<std::string> forward_path;

std::string tmp_file_name;
std::string new_file_name;

timeval now_tv;
char now_date[32];

/////////////////////////////////////////////////////////////////////////////

inline bool black_holed()
{
  if (0 == them_net_addr[0]) // We have no address to check.
    return false;

  return false;
}

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

inline void get_net_addrs()
{
  sockaddr_storage addr;
  socklen_t addr_len;

  addr_len = sizeof addr;
  if (-1 != getsockname(STDIN_FILENO, reinterpret_cast<struct sockaddr*>(&addr),
                        &addr_len)) {
    switch (addr_len) {
    case sizeof(sockaddr_in) : {
      sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(&addr);
      inet_ntop(AF_INET, &(sa->sin_addr), us_net_addr, sizeof us_net_addr);
      break;
    }
    case sizeof(sockaddr_in6) : {
      sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(&addr);
      inet_ntop(AF_INET6, &(sa->sin6_addr), us_net_addr, sizeof us_net_addr);
      break;
    }
    } // switch
  }

  addr_len = sizeof addr;
  if (-1 != getpeername(STDIN_FILENO, reinterpret_cast<struct sockaddr*>(&addr),
                        &addr_len)) {
    switch (addr_len) {
    case sizeof(sockaddr_in) : {
      sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(&addr);
      inet_ntop(AF_INET, &(sa->sin_addr), them_net_addr, sizeof them_net_addr);
      break;
    }
    case sizeof(sockaddr_in6) : {
      sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(&addr);
      inet_ntop(AF_INET6, &(sa->sin6_addr), them_net_addr,
                sizeof them_net_addr);
      break;
    }
    } // switch
  }
}

inline void maildir_names()
{
  errno = 0; // See GETPWNAM(3)
  passwd* pw;
  PCHECK(pw = getpwuid(getuid()));
  const char* homedir = pw->pw_dir;

  PCHECK(gettimeofday(&now_tv, 0) == 0);

  tm* ptm;
  CHECK_NOTNULL(ptm = localtime(&now_tv.tv_sec));
  CHECK_EQ(sizeof now_date - 1, strftime(now_date, sizeof now_date,
                                         "%a, %d %b %Y %H:%M:%S %z", ptm));

  int fdr;
  PCHECK((fdr = open("/dev/urandom", O_RDONLY)) != -1);

  uint64_t randombits;
  PCHECK(read(fdr, &randombits, sizeof randombits) == sizeof randombits);

  PCHECK(close(fdr) == 0);

  // Unique name, see http://cr.yp.to/proto/maildir.html
  std::ostringstream ss;

  ss << now_tv.tv_sec << ".R" << std::hex << std::setfill('0') << std::setw(16)
     << randombits << "." << fqdn;

  std::string uniq = ss.str();

  std::string maildir;

  const char* ev = getenv("MAILDIR");
  if (ev) {
    maildir = ev;
  } else {
    maildir = homedir;
    maildir += "/Maildir";
  }

  tmp_file_name = maildir + "/tmp/" + uniq;
  new_file_name = maildir + "/new/" + uniq;
}

inline bool pregreeting()
{
  // Check stdin to see if it has input.
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(STDIN_FILENO, &rfds);

  // Wait a few seconds...
  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;

  int retval = select(1, &rfds, NULL, NULL, &tv);
  if (-1 == retval) {
    PLOG(ERROR) << "select() failed";
    return false;
  }

  if (retval)
    return true;

  return false;
}

inline void reset()
{
  alarm(5 * 60); // Reset the timeout, too.
  reverse_path.clear();
  forward_path.clear();
}

inline bool save(std::ofstream& tmpfile)
{
  maildir_names();

  tmpfile.open(tmp_file_name);
  if (!tmpfile.is_open()) {
    PLOG(ERROR) << "open(" << tmp_file_name << ") failed";
    return false;
  }

  tmpfile << "Received:" << (them_net_addr[0] ? " from " : "") << them_net_addr
          << " by " << fqdn << "; " << now_date << std::endl;

  tmpfile << "Return-Path:" << reverse_path << std::endl;

  SYSLOG(INFO) << "mail from " << client_identity
               << (them_net_addr[0] ? "[" : "") << them_net_addr
               << (them_net_addr[0] ? "]" : "") << " " << reverse_path
               << " --> " << forward_path[0];

  return true;
}

inline void save_deliver(std::ofstream& tmpfile)
{
  tmpfile.close();
  PCHECK(rename(tmp_file_name.c_str(), new_file_name.c_str()) == 0);
}

inline bool slurp_line(boost::asio::posix::stream_descriptor& in,
                       boost::asio::streambuf& buf, const char* msg)
{
  boost::system::error_code err;

  boost::asio::read_until(in, buf, std::string("\r\n"), err);

  if (boost::asio::error::eof == err) {
    LOG(ERROR) << "eof in " << msg << (them_net_addr[0] ? " from " : "")
               << them_net_addr;
    return false;
  }
  if (err) {
    LOG(ERROR) << "mystery error in " << msg << "err == " << err
               << (them_net_addr[0] ? " from " : "") << them_net_addr;
    return false;
  }
  return true;
}

/////////////////////////////////////////////////////////////////////////////

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
  google::InstallFailureSignalHandler();
  fLI::FLAGS_stderrthreshold = 4; // No stderr for log messages.

  // Set timeout signal handler.
  struct sigaction sact;
  PCHECK(sigemptyset(&sact.sa_mask) == 0);
  sact.sa_flags = 0;
  sact.sa_handler = timeout;
  PCHECK(sigaction(SIGALRM, &sact, NULL) == 0);

  alarm(5 * 60); // Initial timeout set for command loop.

  get_net_addrs();

  utsname un;
  PCHECK(uname(&un) == 0);

  fqdn = un.nodename;
  if ((fqdn.find(".") == std::string::npos) && us_net_addr[0]) {
    std::ostringstream ss;
    ss << "[" << us_net_addr << "]";
    fqdn = ss.str();
  }

  if (them_net_addr[0]) { // If we know a remote address:
    if (black_holed()) {
      std::cout << "554 service unavailable; client [" << them_net_addr
                << "] lost in black hole\r\n";
      SYSLOG(WARNING) << "client black holed " << them_net_addr;
      return 1;
    }

    if (pregreeting()) {
      std::cout << "554 input before greeting\r\n";
      SYSLOG(WARNING) << "pregreeting traffic from " << them_net_addr;
      return 1;
    }
  }

  std::cout << "220 " << fqdn << " ESMTP\r\n" << std::flush;

  boost::asio::io_service io;
  boost::asio::posix::stream_descriptor in(io, STDIN_FILENO);

  boost::asio::streambuf buf;
  std::istream is(&buf);

  while (slurp_line(in, buf, "command loop")) {
    std::string cmd;

    while (is.good()) {
      char ch;
      is.get(ch);
      if (isspace(ch))
        break;
      cmd += toupper(ch);
    }

    if (("EHLO" == cmd) || ("HELO" == cmd)) {
      std::getline(is, client_identity, '\r');
      eat(is, "\n");

      if ((client_identity == fqdn) || (client_identity == "localhost") ||
          (client_identity == "localhost.localdomain")) {
        std::cout << "554 liar\r\n" << std::flush;
        SYSLOG(WARNING) << "liar: " << cmd << (them_net_addr[0] ? " from " : "")
                        << them_net_addr << " claiming " << client_identity;
        return 1;
      }

      if ("EHLO" == cmd) {
        std::cout << "250-" << fqdn << "\r\n"
                  << "250-PIPELINING\r\n"
                  << "250 8BITMIME\r\n" << std::flush;
      } else { // HELO
        std::cout << "250 " << fqdn << "\r\n" << std::flush;
      }
      reset();
      LOG(INFO) << cmd << (them_net_addr[0] ? " from " : "") << them_net_addr
                << " claiming " << client_identity;
      continue;
    }

    if (("MAIL" == cmd) && eat(is, "FROM:")) {
      reset();
      std::getline(is, reverse_path, '\r');
      eat(is, "\n");

      // Do I want to validate this reverse_path at all?
      std::cout << "250 mail ok\r\n" << std::flush;
      continue;
    }

    if (("RCPT" == cmd) && eat(is, "TO:")) {
      // Verify we have a reverse path:
      if (reverse_path.empty()) {
        std::cout << "503 need MAIL before RCPT\r\n" << std::flush;
        continue;
      }

      std::string to;
      std::getline(is, to, '\r');
      eat(is, "\n");

      // parse the "to" address and validate dom
      boost::regex adrx("\\s*<.+@(.+)>");
      boost::cmatch matches;

      if (boost::regex_match(to.c_str(), matches, adrx)) {
        std::string dom(matches[1].first, matches[1].second);
        boost::to_lower(dom);
        if ((fqdn != dom) && ("digilicious.com" != dom) &&
            ("genehightower.com" != dom)) {
          std::cout << "554 relay access denied\r\n" << std::flush;
          LOG(WARNING) << "relay access denied for " << dom;
          continue;
        }
      } else {
        // Mail to local user with no domain could be made to work,
        // but that's not what we do.
        std::cout << "553 bad address\r\n" << std::flush;
        continue;
      }

      forward_path.push_back(to);
      std::cout << "250 rcpt ok\r\n" << std::flush;
      continue;
    }

    if ("DATA" == cmd) {
      // Verify we have a reverse path and at least one recipient address:
      if (reverse_path.empty() || forward_path.empty()) {
        std::cout << "503 need MAIL and RCPT before DATA\r\n" << std::flush;
        continue;
      }

      std::ofstream savefile;

      if (!save(savefile)) {
        std::cout << "554 error saving mail\r\n" << std::flush;
        continue;
      }

      std::cout << "354 go\r\n" << std::flush;

      std::string line;
      std::getline(is, line); // Eat anything up to and including \r\n.

      alarm(10 * 60); // Up the timeout for the DATA transfer.

      while (slurp_line(in, buf, "data loop")) {
        std::getline(is, line);
        if ('\r' == line.at(line.length() - 1))
          line.erase(line.length() - 1, 1);

        if ("." == line) {
          save_deliver(savefile);
          std::cout << "250 data ok\r\n" << std::flush;
          break; // <-- from data loop
        }

        line += '\n'; // Add POSIX style line ending.
        if ('.' == line.at(0))
          line.erase(0, 1); // Eat leading dot.

        savefile << line; // We might want to catch write errors here
      }

      // eof before end of message?

      alarm(5 * 60); // Set the timeout back down for the
                     // command loop.
      continue;
    }

    // All the commands that follow ignore any additional input, so we
    // eat the rest of the line including the \r\n.
    std::string ignore;
    std::getline(is, ignore);

    if ("RSET" == cmd) {
      reset();
      std::cout << "250 ok\r\n" << std::flush;
      continue;
    }

    if ("QUIT" == cmd) {
      std::cout << "221 bye\r\n" << std::flush;
      return 0;
    }

    if ("VRFY" == cmd) {
      std::cout << "252 try it\r\n" << std::flush;
      continue;
    }

    if ("NOOP" == cmd) {
      std::cout << "250 nook\r\n" << std::flush;
      continue;
    }

    if ("HELP" == cmd) {
      std::cout << "214-see https://digilicious.com/smtp.html\r\n"
                << "214 and https://www.ietf.org/rfc/rfc5321.txt\r\n"
                << std::flush;
      continue;
    }

    std::cout << "500 command not recognized or not implemented\r\n"
              << std::flush;
    LOG(WARNING) << "unrecognized command '" << cmd << "'"
                 << (them_net_addr[0] ? " from " : "") << them_net_addr;
  }
}

#include "Message.hpp"

void Message::open(std::string const& fqdn, SpamStatus spam)
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
  ofs_.open(tmpfn_.string());
}

std::ostream& Message::write(char const* s, std::streamsize count)
{
  if (!size_error_ && (count_ + count) <= Config::max_msg_size) {
    count_ += count;
    return ofs_.write(s, count);
  }
  size_error_ = true;
  return ofs_;
}
#include "Message.hpp"

#include <sys/types.h>

#include <sys/stat.h>

void Message::open(std::string_view fqdn,
                   std::streamsize max_size,
                   SpamStatus spam)
{
  max_size_ = max_size;

  auto const maildir{[&] {
    auto const maildir_ev{getenv("MAILDIR")};
    if (maildir_ev) {
      return fs::path(maildir_ev);
    }

    auto homedir{fs::path{}};
    auto const homedir_ev{getenv("HOME")};
    if (homedir_ev) {
      CHECK(strcmp(homedir_ev, "/root")) << "should not run as root";
      homedir = homedir_ev;
    }
    else {
      errno = 0; // See GETPWNAM(3)
      passwd* pw;
      PCHECK(pw = getpwuid(getuid()));
      homedir = pw->pw_dir;
    }
    return homedir / "Maildir";
  }()};

  if (spam == SpamStatus::spam) {
    maildir /= ".Junk";
  }

  // Unique name, see: <https://cr.yp.to/proto/maildir.html>
  auto uniq{std::ostringstream{}};
  uniq << then_.sec() << '.' << 'R' << s_ << '.' << fqdn;

  tmpfn_ = maildir;
  newfn_ = maildir;

  tmpfn_ /= "tmp";
  newfn_ /= "new";

  umask(077);

  // mkdirs for tmpfn_ and newfn_
  error_code ec;
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
  if (!size_error_ && (size_ + count) <= max_size_) {
    size_ += count;
    return ofs_.write(s, count);
  }
  size_error_ = true;
  return ofs_;
}

void Message::save()
{
  if (size_error()) {
    LOG(WARNING) << "message size error: " << size() << " exceeds "
                 << max_size();
  }
  try {
    ofs_.close();
  }
  catch (std::system_error const& e) {
    LOG(ERROR) << e.what();
    return;
  }
  catch (std::exception const& e) {
    LOG(ERROR) << e.what();
    return;
  }

  error_code ec;
  rename(tmpfn_, newfn_, ec);
  if (ec) {
    LOG(ERROR) << "can't rename " << tmpfn_ << " to " << newfn_ << ": " << ec;
  }
}

void Message::trash()
{
  try {
    ofs_.close();
  }
  catch (std::system_error const& e) {
    LOG(ERROR) << e.what();
  }
  catch (std::exception const& e) {
    LOG(ERROR) << e.what();
  }

  error_code ec;
  fs::remove(tmpfn_, ec);
  if (ec) {
    LOG(ERROR) << "can't remove " << tmpfn_ << ": " << ec;
  }
}

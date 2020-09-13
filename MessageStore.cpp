#include "MessageStore.hpp"

#include "osutil.hpp"

#include <cstdlib>

#include <fmt/format.h>
#include <fmt/ostream.h>

namespace {
auto locate_maildir() -> fs::path
{
  auto const maildir_ev{getenv("MAILDIR")};
  if (maildir_ev) {
    return maildir_ev;
  }
  else {
    return osutil::get_home_dir() / "Maildir";
  }
}
} // namespace

void MessageStore::open(std::string_view fqdn,
                        std::streamsize  max_size,
                        std::string_view folder)
{
  max_size_ = max_size;

  auto maildir = locate_maildir();

  if (!folder.empty()) {
    maildir /= folder;
  }

  newfn_  = maildir / "new";
  tmpfn_  = maildir / "tmp";
  tmp2fn_ = maildir / "tmp";

  error_code ec;
  create_directories(newfn_, ec);
  create_directories(tmpfn_, ec);

  // Unique name, see: <https://cr.yp.to/proto/maildir.html>
  auto const uniq{fmt::format("{}.R{}.{}", then_.sec(), s_, fqdn)};
  newfn_ /= uniq;
  tmpfn_ /= uniq;

  auto const uniq2{fmt::format("{}.R{}2.{}", then_.sec(), s_, fqdn)};
  tmp2fn_ /= uniq2;

  // open
  ofs_.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ofs_.open(tmpfn_);
}

std::ostream& MessageStore::write(char const* s, std::streamsize count)
{
  if (!size_error_ && (size_ + count) <= max_size_) {
    size_ += count;
    return ofs_.write(s, count);
  }
  else {
    size_error_ = true;
    return ofs_;
  }
}

void MessageStore::try_close_()
{
  try {
    ofs_.close();
  }
  catch (std::system_error const& e) {
    LOG(ERROR) << e.what() << "code: " << e.code();
  }
  catch (std::exception const& e) {
    LOG(ERROR) << e.what();
  }
}

std::string_view MessageStore::freeze()
{
  try_close_();
  error_code ec;
  rename(tmpfn_, tmp2fn_, ec);
  if (ec) {
    LOG(ERROR) << "can't rename " << tmpfn_ << " to " << tmp2fn_ << ": " << ec;
  }
  ofs_.open(tmpfn_);
  mapping_.open(tmp2fn_);
  size_ = 0;
  return std::string_view(mapping_.data(), mapping_.size());
}

fs::path MessageStore::deliver()
{
  if (size_error()) {
    LOG(WARNING) << "message size error: " << size() << " exceeds "
                 << max_size();
  }

  try_close_();

  error_code ec;
  rename(tmpfn_, newfn_, ec);
  if (ec) {
    LOG(ERROR) << "can't rename " << tmpfn_ << " to " << newfn_ << ": " << ec;
  }

  if (fs::exists(newfn_)) {
    LOG(INFO) << "successfully deliverd " << newfn_;
  }
  else {
    LOG(ERROR) << "failed to deliver " << newfn_;
  }

  if (fs::exists(tmp2fn_)) {
    fs::remove(tmp2fn_, ec);
    if (ec) {
      LOG(ERROR) << "can't remove " << tmp2fn_ << ": " << ec;
    }
  }

  if (mapping_.is_open())
    mapping_.close();

  return newfn_;
}

void MessageStore::trash()
{
  try_close_();

  error_code ec;
  fs::remove(tmpfn_, ec);
  if (ec) {
    LOG(ERROR) << "can't remove " << tmpfn_ << ": " << ec;
  }
  if (fs::exists(tmp2fn_)) {
    fs::remove(tmp2fn_, ec);
    if (ec) {
      LOG(ERROR) << "can't remove " << tmp2fn_ << ": " << ec;
    }
  }
}

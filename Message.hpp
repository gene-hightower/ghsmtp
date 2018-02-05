#ifndef MESSAGE_DOT_HPP
#define MESSAGE_DOT_HPP

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string_view>

#include <pwd.h>
#include <sys/types.h>

#include "Now.hpp"
#include "Pill.hpp"

#include "fs.hpp"

class Message {
public:
  enum class SpamStatus : bool { ham, spam };

  void open(std::string_view fqdn, std::streamsize max_size, SpamStatus spam);

  Pill const& id() const { return s_; }
  Now const& when() const { return then_; }

  std::ostream& write(char const* s, std::streamsize count);
  std::ostream& write(std::string_view s)
  {
    return write(s.data(), s.length());
  }

  bool size_error() const { return size_error_; }
  std::streamsize size() const { return size_; }
  std::streamsize max_size() const { return max_size_; }
  std::streamsize size_left() const { return max_size() - size(); }

  void save()
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
  void trash()
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

private:
  Pill s_;
  Now then_;

  std::ofstream ofs_;
  std::streamsize size_{0};
  std::streamsize max_size_{0};

  fs::path tmpfn_;
  fs::path newfn_;

  bool size_error_{false};
};

#endif // MESSAGE_DOT_HPP

#ifndef MESSAGE_DOT_HPP
#define MESSAGE_DOT_HPP

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string_view>

#include <boost/filesystem.hpp>

#include <pwd.h>
#include <sys/types.h>

#include "Now.hpp"
#include "Pill.hpp"

class Message {
public:
  Message() = default;

  enum class SpamStatus : bool { ham, spam };

  void open(std::string const& fqdn, size_t max_size, SpamStatus spam);

  Pill const& id() const { return s_; }
  Now const& when() const { return then_; }

  std::ostream& write(char const* s, std::streamsize count);
  std::ostream& write(std::string_view s)
  {
    return write(s.data(), s.length());
  }

  bool size_error() const { return size_error_; }
  size_t size() const { return size_; }
  size_t size_left() const { return max_size_ - size_; }

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
  size_t size_{0};
  size_t max_size_{0};

  boost::filesystem::path tmpfn_;
  boost::filesystem::path newfn_;

  bool size_error_{false};
};

#endif // MESSAGE_DOT_HPP

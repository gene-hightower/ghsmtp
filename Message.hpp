#ifndef MESSAGE_DOT_HPP
#define MESSAGE_DOT_HPP

#include <cstdlib>
#include <fstream>
#include <sstream>

#include <experimental/string_view>

#include <boost/filesystem.hpp>

#include <pwd.h>
#include <sys/types.h>

#include "Now.hpp"
#include "Pill.hpp"

class Message {
public:
  Message(std::streamsize max_size)
    : max_size_(max_size)
  {
  }

  enum class SpamStatus : bool { ham, spam };

  void open(std::string const& fqdn, SpamStatus spam);

  Pill const& id() const { return s_; }
  Now const& when() const { return then_; }

  std::ostream& write(char const* s, std::streamsize count);
  std::ostream& write(std::experimental::string_view s)
  {
    return write(s.data(), s.length());
  }

  bool size_error() const { return size_error_; }
  size_t size() const { return count_; }
  size_t size_left() const { return max_size_ - count_; }

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
  size_t count_{0};

  boost::filesystem::path tmpfn_;
  boost::filesystem::path newfn_;

  size_t max_size_;
  bool size_error_{false};
};

#endif // MESSAGE_DOT_HPP

#ifndef MESSAGESTORE_DOT_HPP
#define MESSAGESTORE_DOT_HPP

#include <fstream>
#include <string_view>

#include <boost/iostreams/device/mapped_file.hpp>

#include "Now.hpp"
#include "Pill.hpp"

#include "fs.hpp"

class MessageStore {
public:
  void open(std::string_view fqdn,
            std::streamsize  max_size,
            std::string_view folder);

  Pill const& id() const { return s_; }
  Now const&  when() const { return then_; }

  std::ostream& write(char const* s, std::streamsize count);
  std::ostream& write(std::string_view s)
  {
    return write(s.data(), s.length());
  }

  void deliver();
  void close();
  void trash() { close(); }

  std::string_view freeze();

  bool            size_error() const { return size_error_; }
  std::streamsize size() const { return size_; }
  std::streamsize max_size() const { return max_size_; }
  std::streamsize size_left() const { return max_size() - size(); }

private:
  Pill s_;
  Now  then_;

  std::ofstream   ofs_;
  std::streamsize size_{0};
  std::streamsize max_size_{0};

  fs::path newfn_;
  fs::path tmpfn_;
  fs::path tmp2fn_;

  bool size_error_{false};

  boost::iostreams::mapped_file_source mapping_;

  void try_close_();
};

#endif // MESSAGESTORE_DOT_HPP

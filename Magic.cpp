#include "Magic.hpp"

#include <magic.h>

#include <glog/logging.h>

using std::experimental::string_view;

Magic::Magic()
  : magic_(CHECK_NOTNULL(magic_open(MAGIC_MIME)))
{
  CHECK_EQ(magic_load(magic_, nullptr), 0) << magic_error(magic_);
}

Magic::~Magic() { magic_close(magic_); }

std::string Magic::buffer(string_view bfr) const
{
  auto data = reinterpret_cast<void const*>(bfr.data());
  return CHECK_NOTNULL(magic_buffer(magic_, data, bfr.size()));
}

std::string Magic::file(char const* path) const
{
  return CHECK_NOTNULL(magic_file(magic_, path));
}

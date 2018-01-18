#include "Magic.hpp"

#include <magic.h>

#include <glog/logging.h>

Magic::Magic()
  : magic_(CHECK_NOTNULL(magic_open(MAGIC_MIME)))
{
  CHECK_EQ(magic_load(magic_, nullptr), 0) << magic_error(magic_);
}

Magic::~Magic() { magic_close(magic_); }

auto Magic::buffer(std::string_view bfr) const -> std::string
{
  auto data = reinterpret_cast<void const*>(bfr.data());
  return CHECK_NOTNULL(magic_buffer(magic_, data, bfr.size()));
}

auto Magic::file(char const* path) const -> std::string
{
  return CHECK_NOTNULL(magic_file(magic_, path));
}

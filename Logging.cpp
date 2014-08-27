#define DLL_IMPLEMENTATION
#include "Logging.hpp"
#include "dll_spec.h"

#include <sstream>

namespace Logging {

char const* DLL_SPEC program_name = nullptr;
int DLL_SPEC log_fd = STDERR_FILENO;

CheckOpMessageBuilder::CheckOpMessageBuilder(const char* exprtext)
  : stream_(new std::ostringstream)
{
  *stream_ << exprtext << " (";
}

CheckOpMessageBuilder::~CheckOpMessageBuilder()
{
  delete stream_;
}

std::ostream* CheckOpMessageBuilder::ForVar2()
{
  *stream_ << " vs. ";
  return stream_;
}

std::string* CheckOpMessageBuilder::NewString()
{
  *stream_ << ")";
  return new std::string(stream_->str());
}
}

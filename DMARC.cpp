#include "DMARC.hpp"

namespace {
u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>((cp)));
}
} // namespace

namespace DMARC {
}

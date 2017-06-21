#include "Domain.hpp"

#include <idn-free.h>
#include <idna.h>
#include <stringprep.h>

#include <glog/logging.h>

Domain::Domain(char const* dom)
{
  set(dom);
}

void Domain::set(char const* dom)
{
  if (ascii_)
    idn_free(ascii_);
  if (utf8_)
    idn_free(utf8_);

  // Normalize to avoid fuckery.
  auto norm = stringprep_utf8_nfkc_normalize(dom, -1);

  auto code = idna_to_ascii_8z(norm, &ascii_, IDNA_USE_STD3_ASCII_RULES);
  if (code != IDNA_SUCCESS) {
    throw std::runtime_error(idna_strerror(static_cast<Idna_rc>(code)));
  }
  code = idna_to_unicode_8z8z(ascii_, &utf8_, IDNA_USE_STD3_ASCII_RULES);
  if (code != IDNA_SUCCESS) {
    throw std::runtime_error(idna_strerror(static_cast<Idna_rc>(code)));
  }

  idn_free(norm);
}

Domain::~Domain()
{
  if (ascii_)
    idn_free(ascii_);
  if (utf8_)
    idn_free(utf8_);
}

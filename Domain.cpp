#include "Domain.hpp"
#include "IP4.hpp"

#include <idn-free.h>
#include <idna.h>
#include <stringprep.h>

#include <glog/logging.h>

Domain::Domain(char const* dom) { set(dom); }

void Domain::set(char const* dom)
{
  if (IP4::is_bracket_address(dom)) {
    ascii_ = dom;
    utf8_ = dom;
    return;
  }

  // Normalize to avoid fuckery.
  auto norm = stringprep_utf8_nfkc_normalize(dom, -1);

  char* ptr = nullptr;
  auto code = idna_to_ascii_8z(norm, &ptr, IDNA_USE_STD3_ASCII_RULES);
  if (code != IDNA_SUCCESS) {
    idn_free(norm);
    throw std::runtime_error(idna_strerror(static_cast<Idna_rc>(code)));
  }
  ascii_ = ptr;
  idn_free(ptr);

  ptr = nullptr;
  code = idna_to_unicode_8z8z(ascii_.c_str(), &ptr, IDNA_USE_STD3_ASCII_RULES);
  if (code != IDNA_SUCCESS) {
    idn_free(norm);
    throw std::runtime_error(idna_strerror(static_cast<Idna_rc>(code)));
  }
  utf8_ = ptr;
  idn_free(ptr);

  idn_free(norm);
}

void Domain::clear()
{
  ascii_.clear();
  utf8_.clear();
}

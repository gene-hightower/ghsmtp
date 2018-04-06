#include "Domain.hpp"

#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include <algorithm>

#include <idn2.h>
#include <uninorm.h>

#include <glog/logging.h>

#include <stdexcept>

// Normalization Form KC (NFKC) Compatibility Decomposition, followed
// by Canonical Composition, see <http://unicode.org/reports/tr15/>

std::string nfkc(std::string_view str)
{
  size_t length = 0;
  auto udata = reinterpret_cast<const uint8_t*>(str.data());
  auto norm = u8_normalize(UNINORM_NFKC, udata, str.size(), nullptr, &length);
  std::string str_norm(reinterpret_cast<const char*>(norm), length);
  free(norm);
  return str_norm;
}

void Domain::set(std::string_view dom)
{
  // Handle "bare" IP addresses, without the brackets.
  if (IP4::is_address(dom)) {
    ascii_ = IP4::to_address_literal(dom);
    utf8_ = ascii_;
    lc_ = ascii_;
    is_address_literal_ = true;
    return;
  }
  if (IP6::is_address(dom)) {
    ascii_ = IP6::to_address_literal(dom);
    utf8_ = ascii_;
    lc_ = ascii_;
    is_address_literal_ = true;
    return;
  }

  if (IP4::is_address_literal(dom) || IP6::is_address_literal(dom)) {
    ascii_ = std::string(dom.data(), dom.length());
    utf8_ = ascii_;
    lc_ = ascii_;
    is_address_literal_ = true;
    return;
  }

  // Since all Domains are fully qualified and not just some bag of
  // labels, the dot provides no real information and will mess up
  // name matching on certs and stuff.

  dom = remove_trailing_dot(dom);

  auto norm = nfkc(dom);

  char* ptr = nullptr;
  auto code = idn2_to_ascii_8z(norm.data(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    throw std::runtime_error(idn2_strerror(code));
  }
  ascii_ = ptr;
  idn2_free(ptr);

  ptr = nullptr;
  code = idn2_to_unicode_8z8z(ascii_.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    throw std::runtime_error(idn2_strerror(code));
  }
  utf8_ = ptr;
  idn2_free(ptr);

  lc_.resize(ascii_.length());
  std::transform(ascii_.begin(), ascii_.end(), lc_.begin(), ::tolower);
}

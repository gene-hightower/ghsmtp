#include "Domain.hpp"

#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include <algorithm>

#include <idn2.h>
#include <uninorm.h>

#include <glog/logging.h>

#include <stdexcept>

namespace {
size_t constexpr max_length = 255;
}

// Normalization Form KC (NFKC) Compatibility Decomposition, followed
// by Canonical Composition, see <http://unicode.org/reports/tr15/>

std::string nfkc(std::string_view str)
{
  size_t length = max_length;
  char   bfr[max_length];
  CHECK_LE(str.length(), max_length);
  auto udata = reinterpret_cast<uint8_t const*>(str.data());
  auto ubfr  = reinterpret_cast<uint8_t*>(bfr);
  CHECK_NOTNULL(u8_normalize(UNINORM_NFKC, udata, str.size(), ubfr, &length));
  return std::string{bfr, length};
}

bool Domain::validate(std::string_view dom)
{
  if (dom.length() > max_length) {
    return false;
  }

  // Handle "bare" IP addresses, without the brackets.
  if (IP::is_address(dom)) {
    return true;
  }

  if (IP::is_address_literal(dom)) {
    return true;
  }

  dom = remove_trailing_dot(dom);

  auto const norm = nfkc(dom);

  // idn2_to_ascii_8z() converts (ASCII) to lower case

  char* ptr  = nullptr;
  auto  code = idn2_to_ascii_8z(norm.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK)
    return false;
  std::string ascii(ptr);
  idn2_free(ptr);

  ptr  = nullptr;
  code = idn2_to_unicode_8z8z(ascii.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK)
    return false;
  idn2_free(ptr);

  // FIXME: check syntax is dot-string?

  return true;
}

void Domain::set(std::string_view dom)
{
  if (dom.length() > max_length) {
    throw std::invalid_argument("domain name too long");
  }

  // Handle "bare" IP addresses, without the brackets.
  if (IP::is_address(dom)) {
    ascii_              = IP::to_address_literal(dom);
    utf8_               = ascii_;
    is_address_literal_ = true;
    return;
  }

  if (IP::is_address_literal(dom)) {
    ascii_              = std::string(dom.data(), dom.length());
    utf8_               = ascii_;
    is_address_literal_ = true;
    return;
  }

  is_address_literal_ = false;

  // Since all Domains are fully qualified and not just some bag of
  // labels, the trailing dot provides no real information and will
  // mess up name matching on certs and stuff.

  dom = remove_trailing_dot(dom);

  auto const norm = nfkc(dom);

  // idn2_to_ascii_8z() converts (ASCII) to lower case

  char* ptr  = nullptr;
  auto  code = idn2_to_ascii_8z(norm.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK)
    throw std::invalid_argument(idn2_strerror(code));
  ascii_ = ptr;
  idn2_free(ptr);

  ptr  = nullptr;
  code = idn2_to_unicode_8z8z(ascii_.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK)
    throw std::invalid_argument(idn2_strerror(code));
  utf8_ = ptr;
  idn2_free(ptr);
}

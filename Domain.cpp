#include "Domain.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include <idn2.h>
#include <uninorm.h>

#include <glog/logging.h>

#include <stdexcept>

using namespace std::string_literals;

namespace {
std::string nfkc(std::experimental::string_view str)
{
  size_t length = 0;
  auto udata = reinterpret_cast<const uint8_t*>(str.data());
  auto norm = u8_normalize(UNINORM_NFKC, udata, str.size(), nullptr, &length);
  std::string str_norm(reinterpret_cast<const char*>(norm), length);
  free(norm);
  return str_norm;
}
}

void Domain::set(std::experimental::string_view dom)
{
  // Handle "bare" IP address literals, without the brackets.
  if (IP4::is_address(dom)) {
    ascii_ = IP4::to_address_literal(dom);
    utf8_ = ascii_;
    is_address_literal_ = true;
    return;
  }
  if (IP6::is_address(dom)) {
    ascii_ = IP6::to_address_literal(dom);
    utf8_ = ascii_;
    is_address_literal_ = true;
    return;
  }

  if (IP4::is_address_literal(dom) || IP6::is_address_literal(dom)) {
    ascii_ = std::string(dom.data(), dom.length());
    utf8_ = ascii_;
    is_address_literal_ = true;
    return;
  }

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
}

void Domain::clear()
{
  ascii_.clear();
  utf8_.clear();
  is_address_literal_ = false;
}

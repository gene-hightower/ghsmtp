#include "Domain.hpp"

#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include <algorithm>

#include <idn2.h>
#include <uninorm.h>

#include <glog/logging.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

#include <stdexcept>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

namespace RFC5321 {
#include "UTF8.hpp"

using dot   = one<'.'>;
using dash  = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, UTF8_non_ascii> {};

struct u_ldh_tail : star<sor<seq<plus<dash>, u_let_dig>, u_let_dig>> {};

struct u_label : seq<u_let_dig, u_ldh_tail> {};

struct let_dig : sor<ALPHA, DIGIT> {};

struct ldh_tail : star<sor<seq<plus<dash>, let_dig>, let_dig>> {};

struct ldh_str : seq<let_dig, ldh_tail> {};

struct sub_domain : u_label {};

struct domain : list_tail<sub_domain, dot> {};
};

namespace {
size_t constexpr max_length = 255;

bool is_domain(std::string_view dom)
{
  auto in{memory_input<>(dom.data(), dom.size(), "domain")};
  return tao::pegtl::parse<RFC5321::domain>(in);
}

bool domain_check(std::string_view dom)
{
  if (dom.empty()) {
    return true; // domains in email addresses can be empty
  }

  if (!is_domain(dom)) {
    LOG(ERROR) << "failed to parse «" << dom << "» as domain";
    return false;
  }

  /*
   * Allow "localhost" amung others.

  std::string domain(dom.data(), dom.length());

  auto labels{std::vector<std::string>{}};
  boost::algorithm::split(labels, domain, boost::algorithm::is_any_of("."));

  if (labels.size() < 2) {
    LOG(ERROR) << "domain «" << dom << "» must have two or more labels";
    return false;
  }

  if (labels[labels.size() - 1].length() < 2) {
    LOG(ERROR) << "TLD must be two or more chars in «" << dom << "»";
    return false;
  }
  */

  return true;
}
} // namespace

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

  if (!domain_check(ascii)) {
    return false;
  }

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

  if (!domain_check(ascii_)) {
    throw std::invalid_argument("domain not correct");
  }
}

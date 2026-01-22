#include "Domain.hpp"

// Domains as used in email and as implemented (ie constrained) by the DNS.

#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include "is_ascii.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

#include <idn2.h>
#include <uninorm.h>

#include <glog/logging.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

using namespace tao::pegtl;
using namespace tao::pegtl::abnf;

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

namespace RFC5321 {
#include "UTF8.hpp"

using dot  = one<'.'>;
using dash = one<'-'>;

struct u_let_dig : sor<ALPHA, DIGIT, one<'_'>, UTF8_non_ascii> {};

struct u_ldh_tail : star<sor<seq<plus<dash>, u_let_dig>, u_let_dig>> {};

struct u_label : seq<u_let_dig, u_ldh_tail> {};

struct let_dig : sor<ALPHA, DIGIT, one<'_'>> {};

struct ldh_tail : star<sor<seq<plus<dash>, let_dig>, let_dig>> {};

struct ldh_str : seq<let_dig, ldh_tail> {};

struct sub_domain : u_label {};

struct domain : list_tail<sub_domain, dot> {};

struct domain_only : seq<domain, eof> {};

}; // namespace RFC5321

namespace {
// Maximum length of a domain in dotted-quad notation.
size_t constexpr max_dom_length = 253; // RFC-1035 section 3.1
size_t constexpr max_lab_length = 63;
} // namespace

template <>
struct fmt::formatter<Domain> : ostream_formatter {};

namespace domain {
bool is_fully_qualified(Domain const& dom, std::string& msg)
{
  if (dom.empty()) {
    msg = "empty domain";
    return false;
  }

  auto labels{std::vector<std::string>{}};
  boost::algorithm::split(labels, dom.ascii(),
                          boost::algorithm::is_any_of("."));

  if (labels.size() < 2) {
    msg = fmt::format("domain «{}» must have two or more labels", dom);
    return false;
  }

  if (labels[labels.size() - 1].length() < 2) {
    msg = fmt::format("TLD «{}» must be two or more octets",
                      labels[labels.size() - 1]);
    return false;
  }

  msg.clear();
  return true;
}
} // namespace domain

struct free_deleter {
  template <typename T>
  void operator()(T* p) const
  {
    std::free(const_cast<std::remove_const_t<T>*>(p));
  }
};

template <typename T>
using uc_ptr = std::unique_ptr<T, free_deleter>;
static_assert(sizeof(char*) == sizeof(uc_ptr<char>), ""); // to be sure

std::string_view remove_trailing_dot(std::string_view a)
{
  if (a.length() && (a.back() == '.')) {
    a.remove_suffix(1);
  }
  return a;
}

bool Domain::set_(std::string_view dom, bool should_throw, std::string& msg)
{
  msg.clear(); // no error

  if (IP::is_address_literal(dom)) {
    ascii_ = dom;
    utf8_.clear();
    is_address_literal_ = true;
    return true;
  }

  // A dotted quad IPv4 address will match the syntax of RFC-5321
  // Domain, but should not be confused as a DNS domain.

  if (IP::is_address(dom)) {
    ascii_ = IP::to_address_literal(dom);
    utf8_.clear();
    is_address_literal_ = true;
    return true;
  }

  dom = remove_trailing_dot(dom);

  if (dom.empty()) {
    clear();
    return true;
  }

  auto in{memory_input<>(dom.data(), dom.size(), "domain")};
  if (!tao::pegtl::parse<RFC5321::domain_only>(in)) {
    if (should_throw) {
      throw std::invalid_argument("failed to parse domain");
    }
    msg = fmt::format("failed to parse domain «{}»", dom);
    return false;
  }

  /* ASCII case:
   */

  if (is_ascii(dom)) {
    if (dom.length() > max_dom_length) {
      if (should_throw)
        throw std::invalid_argument("domain name too long");
      msg = fmt::format("domain name «{}» too long", dom);
      return false;
    }

    // Check for domain /label/ too long.
    auto lst = dom.begin();
    for (;;) {
      auto const lab = std::find(lst, dom.end(), '.');
      auto const len = size_t(std::distance(lst, lab));
      if (len > max_lab_length) {
        if (should_throw)
          throw std::invalid_argument("domain label too long");
        msg = fmt::format("domain label «{}» too long",
                          std::string_view{lst, len});
        return false;
      }
      if (lab == dom.end())
        break;

      lst = lab + 1;
    }

    // Map domains to lower case.
    ascii_.clear();
    ascii_.reserve(dom.length());
    std::transform(dom.begin(), dom.end(), std::back_inserter(ascii_),
                   [](unsigned char ch) { return std::tolower(ch); });
    utf8_.clear();
    is_address_literal_ = false;

    return true;
  }

  /* Unicode (UTF-8) case:
   */

  // Normalization Form KC (NFKC) Compatibility Decomposition, followed
  // by Canonical Composition, see <http://unicode.org/reports/tr15/>

  size_t          length = 0;
  uc_ptr<uint8_t> normp(
      u8_normalize(UNINORM_NFKC, reinterpret_cast<uint8_t const*>(dom.data()),
                   dom.size(), nullptr, &length));

  if (!normp) {
    auto const errmsg = std::strerror(errno);
    if (should_throw)
      throw std::invalid_argument(errmsg);
    msg = fmt::format("u8_normalize(\"{}\") failed: ", dom, errmsg);
    return false;
  }

  std::string norm{reinterpret_cast<char*>(normp.get()),
                   length}; // idn2_to_ascii_8z() needs a NUL terminated c_str

  // idn2_to_ascii_8z() converts (ASCII) to lower case

  char* ptr  = nullptr;
  auto  code = idn2_to_ascii_8z(norm.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    if (code == IDN2_TOO_BIG_DOMAIN) {
      if (should_throw)
        throw std::invalid_argument("domain name too long");
      msg = fmt::format("domain name «{}» too long", norm);
      return false;
    }
    if (code == IDN2_TOO_BIG_LABEL) {
      if (should_throw)
        throw std::invalid_argument("domain label too long");
      msg = fmt::format("domain label «{}» too long", norm);
      return false;
    }
    auto const errmsg = idn2_strerror(code);
    if (should_throw)
      throw std::invalid_argument(errmsg);
    msg =
        fmt::format("idn2_to_ascii_8z(\"{}\", …, IDN2_TRANSITIONAL) failed: {}",
                    norm, errmsg);
    return false;
  }
  std::string ascii{ptr};
  idn2_free(ptr);

  // We do an additional check since idn2_to_ascii_8z checks for >255,
  // and we know DNS packet encoding makes the actual limit 253.
  if (ascii.length() > max_dom_length) {
    if (should_throw)
      throw std::invalid_argument("domain name too long");
    msg = fmt::format("domain name «{}» too long", ascii);
    return false;
  }

  ptr  = nullptr;
  code = idn2_to_unicode_8z8z(ascii.c_str(), &ptr, IDN2_TRANSITIONAL);
  if (code != IDN2_OK) {
    auto errmsg = idn2_strerror(code);
    if (should_throw)
      throw std::invalid_argument(errmsg);
    msg = fmt::format(
        "idn2_to_unicode_8z8z(\"{}\", …, IDN2_TRANSITIONAL) failed: {}", ascii,
        errmsg);
    return false;
  }
  CHECK_NOTNULL(ptr);
  std::string utf8{ptr};
  idn2_free(ptr);

  // Identical byte string: not sure this can or should ever happen.
  if (utf8 == ascii) {
    utf8.clear();
  }

  ascii_              = ascii;
  utf8_               = utf8;
  is_address_literal_ = false;

  return true;
}

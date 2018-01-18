#include "DKIM.hpp"

#include <cstdbool> // needs to be above <dkim.h>

#ifdef __clang__
using _Bool = bool; // Not nice to use _Bool in a public interface.
#endif

#include <dkim.h>

#include <glog/logging.h>

namespace {
// Not nice to use "unsigned char" for character data.
auto constexpr uc(char const* cp) -> u_char*
{
  return reinterpret_cast<u_char*>(const_cast<char*>(cp));
}

auto constexpr c(unsigned char* ucp) -> char const*
{
  return reinterpret_cast<char const*>(ucp);
}

constexpr unsigned char id_v[]{"OpenDKIM::Verify"};
constexpr unsigned char id_s[]{"OpenDKIM::Verify"};
} // namespace

namespace OpenDKIM {

Lib::Lib()
  : lib_(CHECK_NOTNULL(dkim_init(nullptr, nullptr)))
{
}

Lib::~Lib()
{
  dkim_free(dkim_);
  dkim_close(lib_);
}

auto Lib::header(std::string_view header) -> void
{
  if (header.size() && header.back() == '\n')
    header.remove_suffix(1);
  if (header.size() && header.back() == '\r')
    header.remove_suffix(1);

  CHECK_EQ((status_ = dkim_header(dkim_, uc(header.data()), header.length())),
           DKIM_STAT_OK)
      << "dkim_header error: " << dkim_getresultstr(status_);

  // LOG(INFO) << "processed: " << std::string(header.data(),
  // header.length());
}

auto Lib::eoh() -> void
{
  status_ = dkim_eoh(dkim_);
  switch (status_) {
  case DKIM_STAT_OK:
  case DKIM_STAT_NOSIG:
    // all good
    break;

  default:
    LOG(ERROR) << "dkim_eoh error: " << dkim_getresultstr(status_);
    break;
  }
}

auto Lib::body(std::string_view body) -> void
{
  CHECK_EQ((status_ = dkim_body(dkim_, uc(body.data()), body.length())),
           DKIM_STAT_OK)
      << "dkim_body error: " << dkim_getresultstr(status_);
}

auto Lib::chunk(std::string_view chunk) -> void
{
  CHECK_EQ((status_ = dkim_chunk(dkim_, uc(chunk.data()), chunk.length())),
           DKIM_STAT_OK)
      << "dkim_chunk error: " << dkim_getresultstr(status_);
}

auto Lib::eom() -> void
{
  status_ = dkim_eom(dkim_, nullptr);

  switch (status_) {
  case DKIM_STAT_OK:
  case DKIM_STAT_NOSIG:
    // all good
    break;

  default:
    LOG(ERROR) << "dkim_eom error: " << dkim_getresultstr(status_);
    break;
  }
}

auto Verify::foreach_sig(
    std::function<void(char const* domain, bool passed)> func) -> void
{
  auto nsigs{0};
  auto sigs{(DKIM_SIGINFO**){}};
  status_ = dkim_getsiglist(dkim_, &sigs, &nsigs);
  if (status_ == DKIM_STAT_INVALID) {
    LOG(WARNING) << "skipping DKIM sigs";
    return;
  }
  CHECK_EQ(status_, DKIM_STAT_OK);

  for (auto i = 0; i < nsigs; ++i) {
    auto const dom = CHECK_NOTNULL(dkim_sig_getdomain(sigs[i]));

    auto const flg = dkim_sig_getflags(sigs[i]);
    if ((flg & DKIM_SIGFLAG_IGNORE) != 0) {
      LOG(INFO) << "ignoring signature for domain " << dom;
      continue;
    }
    if ((flg & DKIM_SIGFLAG_TESTKEY) != 0) {
      LOG(INFO) << "testkey for domain " << dom;
    }

    if ((flg & DKIM_SIGFLAG_PROCESSED) == 0) {
      LOG(INFO) << "ignoring unprocessed sig for domain " << dom;
      continue;
    }

    auto const bh = dkim_sig_getbh(sigs[i]);
    if (bh != DKIM_SIGBH_MATCH) {
      LOG(INFO) << "body hash mismatch for domain " << dom;
    }

    auto bits{0u};
    status_ = dkim_sig_getkeysize(sigs[i], &bits);
    if (status_ == DKIM_STAT_OK) {
      if (bits < 1024) {
        LOG(WARNING) << "keysize " << bits << " too small for domain " << dom;
      }
    }
    else {
      LOG(WARNING) << "getkeysize failed for domain " << dom << " with "
                   << dkim_getresultstr(status_);
    }

    auto const passed
        = ((flg & DKIM_SIGFLAG_PASSED) != 0) && (bh == DKIM_SIGBH_MATCH);

    func(reinterpret_cast<char const*>(dom), passed);
  }
}

Verify::Verify()
{
  dkim_ = CHECK_NOTNULL(dkim_verify(lib_, id_v, nullptr, &status_));
}

auto Verify::check() -> bool
{
  auto nsigs{0};
  auto sigs{(DKIM_SIGINFO**){}};
  status_ = dkim_getsiglist(dkim_, &sigs, &nsigs);
  CHECK_EQ(status_, DKIM_STAT_OK);

  LOG(INFO) << "nsigs == " << nsigs;

  for (auto i = 0; i < nsigs; ++i) {
    LOG(INFO) << i << " domain == " << dkim_sig_getdomain(sigs[i]);
    auto flg = dkim_sig_getflags(sigs[i]);
    if ((flg & DKIM_SIGFLAG_IGNORE) != 0) {
      LOG(INFO) << "DKIM_SIGFLAG_IGNORE";
    }
    if ((flg & DKIM_SIGFLAG_PROCESSED) != 0) {
      LOG(INFO) << "DKIM_SIGFLAG_PROCESSED";
    }
    if ((flg & DKIM_SIGFLAG_PASSED) != 0) {
      LOG(INFO) << "DKIM_SIGFLAG_PASSED";
    }
    if ((flg & DKIM_SIGFLAG_TESTKEY) != 0) {
      LOG(INFO) << "DKIM_SIGFLAG_TESTKEY";
    }
    if ((flg & DKIM_SIGFLAG_NOSUBDOMAIN) != 0) {
      LOG(INFO) << "DKIM_SIGFLAG_NOSUBDOMAIN";
    }
  }

  if (nsigs) {
    auto sig = dkim_getsignature(dkim_);
    if (sig) {

      LOG(INFO) << "dkim_getsignature domain == " << dkim_sig_getdomain(sig);

      auto msglen{ssize_t{}};
      auto canonlen{ssize_t{}};
      auto signlen{ssize_t{}};

      status_ = dkim_sig_getcanonlen(dkim_, sig, &msglen, &canonlen, &signlen);

      CHECK_EQ(status_, DKIM_STAT_OK);

      LOG(INFO) << "msglen == " << msglen;
      LOG(INFO) << "canonlen == " << canonlen;
      LOG(INFO) << "signlen == " << signlen;

      auto nhdrs{0u};
      status_ = dkim_sig_getsignedhdrs(dkim_, sig, nullptr, 0, &nhdrs);
      if (status_ != DKIM_STAT_NORESOURCE) {
        return false;
      }

      LOG(INFO) << "nhdrs == " << nhdrs;

      auto constexpr hdr_sz{DKIM_MAXHEADER + 1};
      auto signedhdrs{std::vector<unsigned char>(nhdrs * hdr_sz, '\0')};

      status_
          = dkim_sig_getsignedhdrs(dkim_, sig, &signedhdrs[0], hdr_sz, &nhdrs);
      CHECK_EQ(status_, DKIM_STAT_OK);

      for (auto i = 0u; i < nhdrs; ++i)
        LOG(INFO) << &signedhdrs[i * hdr_sz];

      return true;
    }
  }

  return false;
}

auto Verify::sig_syntax(std::string_view sig) -> bool
{
  return dkim_sig_syntax(dkim_, uc(sig.data()), sig.length()) == DKIM_STAT_OK;
}

Sign::Sign(char const* secretkey,
           char const* selector,
           char const* domain,
           body_type typ)
{
  dkim_ = CHECK_NOTNULL(dkim_sign(
      lib_, id_s, nullptr, uc(secretkey), uc(selector), uc(domain),
      DKIM_CANON_RELAXED,
      (typ == body_type::binary) ? DKIM_CANON_SIMPLE : DKIM_CANON_RELAXED,
      DKIM_SIGN_RSASHA256, -1, &status_));
}

auto Sign::getsighdr() -> std::string
{
  auto const initial{strlen(DKIM_SIGNHEADER) + 2};
  auto buf{(unsigned char*){}};
  auto len{size_t{0}};
  status_ = dkim_getsighdr_d(dkim_, initial, &buf, &len);
  return std::string(c(buf), len);
}
} // namespace OpenDKIM

#include "OpenDKIM.hpp"

#include "iobuffer.hpp"

#include <stdbool.h> // needs to be above <dkim.h>

#include <dkim.h>

#include <glog/logging.h>

namespace {
// Not nice to use "unsigned char" for character data.
u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>(cp));
}

char const* c(unsigned char* ucp) { return reinterpret_cast<char const*>(ucp); }

constexpr unsigned char id_v[]{"DKIM::verify"};
constexpr unsigned char id_s[]{"DKIM::sign"};
} // namespace

namespace OpenDKIM {

lib::lib()
  : lib_(CHECK_NOTNULL(dkim_init(nullptr, nullptr)))
{
}

lib::~lib()
{
  dkim_free(dkim_);
  dkim_close(lib_);
}

void lib::header(std::string_view header)
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

void lib::eoh()
{
  status_ = dkim_eoh(dkim_);
  switch (status_) {
  case DKIM_STAT_OK:
  case DKIM_STAT_NOSIG:
    // all good
    break;

  default:
    LOG(WARNING) << "dkim_eoh error: " << dkim_getresultstr(status_);
    break;
  }
}

void lib::body(std::string_view body)
{
  CHECK_EQ((status_ = dkim_body(dkim_, uc(body.data()), body.length())),
           DKIM_STAT_OK)
      << "dkim_body error: " << dkim_getresultstr(status_);
}

void lib::chunk(std::string_view chunk)
{
  CHECK_EQ((status_ = dkim_chunk(dkim_, uc(chunk.data()), chunk.length())),
           DKIM_STAT_OK)
      << "dkim_chunk error: " << dkim_getresultstr(status_);
}

void lib::eom()
{
  status_ = dkim_eom(dkim_, nullptr);

  switch (status_) {
  case DKIM_STAT_OK:
  case DKIM_STAT_NOSIG:
    // all good
    break;

  default:
    LOG(WARNING) << "dkim_eom error: " << dkim_getresultstr(status_);
    break;
  }
}

//.............................................................................

sign::sign(char const* secretkey,
           char const* selector,
           char const* domain,
           body_type   typ)
{
  // clang-format off
  dkim_ = dkim_sign(lib_,
                    id_s,
                    nullptr,
                    uc(secretkey),
                    uc(selector),
                    uc(domain),
                    DKIM_CANON_RELAXED,
                    (typ == body_type::binary) ? DKIM_CANON_SIMPLE
                                               : DKIM_CANON_RELAXED,
                    DKIM_SIGN_RSASHA256,
                    -1,
                    &status_);
  // clang-format on
  CHECK_NOTNULL(dkim_);
  CHECK_EQ(status_, DKIM_STAT_OK);

  char const* hdrlist[] = {"cc",
                           "content-language",
                           "content-transfer-encoding",
                           "date",
                           "feedback-id",
                           "from",
                           "in-reply-to",
                           "list-archive",
                           "list-help",
                           "list-id",
                           "list-owner",
                           "list-post",
                           "list-subscribe",
                           "list-unsubscribe",
                           "message-id",
                           "mime-version",
                           "precedence",
                           "references",
                           "reply-to",
                           "resent-cc",
                           "resent-date",
                           "resent-from",
                           "resent-to",
                           "subject",
                           "to",
                           nullptr};

  dkim_signhdrs(dkim_, hdrlist);
}

std::string sign::getsighdr()
{
  auto const     initial{strlen(DKIM_SIGNHEADER) + 2};
  unsigned char* buf = nullptr;
  size_t         len = 0;
  status_            = dkim_getsighdr_d(dkim_, initial, &buf, &len);
  return std::string(c(buf), len);
}

//.............................................................................

void verify::foreach_sig(std::function<void(char const* domain,
                                            bool        passed,
                                            char const* identity,
                                            char const* selector,
                                            char const* b)> func)
{
  int            nsigs = 0;
  DKIM_SIGINFO** sigs  = nullptr;
  status_              = dkim_getsiglist(dkim_, &sigs, &nsigs);
  if (status_ == DKIM_STAT_INVALID) {
    LOG(WARNING) << "skipping DKIM sigs";
    return;
  }
  CHECK_EQ(status_, DKIM_STAT_OK);

  iobuffer<u_char> identity(4 * 1024);

  for (auto i{0}; i < nsigs; ++i) {
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

    auto const passed =
        ((flg & DKIM_SIGFLAG_PASSED) != 0) && (bh == DKIM_SIGBH_MATCH);

    CHECK_EQ(
        dkim_sig_getidentity(dkim_, sigs[i], identity.data(), identity.size()),
        DKIM_STAT_OK);

    auto const selector = dkim_sig_getselector(sigs[i]);

    auto const b = dkim_sig_gettagvalue(sigs[i], false, uc("b"));

    func(c(dom), passed, c(identity.data()), c(selector), c(b));
  }
}

verify::verify()
{
  dkim_ = CHECK_NOTNULL(dkim_verify(lib_, id_v, nullptr, &status_));
}

bool verify::check()
{
  int            nsigs = 0;
  DKIM_SIGINFO** sigs  = nullptr;
  status_              = dkim_getsiglist(dkim_, &sigs, &nsigs);
  CHECK_EQ(status_, DKIM_STAT_OK);

  LOG(INFO) << "nsigs == " << nsigs;

  for (auto i{0}; i < nsigs; ++i) {
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
    auto sig{dkim_getsignature(dkim_)};
    if (sig) {

      LOG(INFO) << "dkim_getsignature domain == " << dkim_sig_getdomain(sig);

      ssize_t msglen;
      ssize_t canonlen;
      ssize_t signlen;

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

      status_ =
          dkim_sig_getsignedhdrs(dkim_, sig, &signedhdrs[0], hdr_sz, &nhdrs);
      CHECK_EQ(status_, DKIM_STAT_OK);

      for (auto i{0u}; i < nhdrs; ++i)
        LOG(INFO) << &signedhdrs[i * hdr_sz];

      return true;
    }
  }

  return false;
}

bool verify::sig_syntax(std::string_view sig)
{
  return dkim_sig_syntax(dkim_, uc(sig.data()), sig.length()) == DKIM_STAT_OK;
}

} // namespace OpenDKIM

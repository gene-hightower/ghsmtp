#ifndef DKIM_DOT_HPP
#define DKIM_DOT_HPP

#include <cstdbool>

#include <experimental/string_view>

#include <dkim.h>

#include <glog/logging.h>

namespace OpenDKIM {

constexpr u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>((cp)));
}

constexpr unsigned char id[]{"OpenDKIM::Verify"};

class Verify;

class Lib {
public:
  Lib()
    : lib_(CHECK_NOTNULL(dkim_init(nullptr, nullptr)))
  {
  }
  ~Lib() { dkim_close(lib_); }

private:
  DKIM_LIB* lib_{nullptr};

  friend class Verify;
};

class Verify {
public:
  Verify(Lib& lib)
    : dkim_(CHECK_NOTNULL(dkim_verify(lib.lib_, id, nullptr, &status_)))
  {
  }

  void header(std::experimental::string_view header)
  {
    if (header.back() == '\n')
      header.remove_suffix(1);
    if (header.back() == '\r')
      header.remove_suffix(1);

    CHECK_EQ((status_ = dkim_header(dkim_, uc(header.data()), header.length())),
             DKIM_STAT_OK)
        << "dkim_header error: " << dkim_getresultstr(status_);

    // LOG(INFO) << "processed: " << std::string(header.data(),
    // header.length());
  }

  void eoh()
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

  void body(std::experimental::string_view body)
  {
    CHECK_EQ((status_ = dkim_body(dkim_, uc(body.data()), body.length())),
             DKIM_STAT_OK)
        << "dkim_body error: " << dkim_getresultstr(status_);
  }

  void eom()
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

  void chunk(std::experimental::string_view chunk)
  {
    CHECK_EQ((status_ = dkim_chunk(dkim_, uc(chunk.data()), chunk.length())),
             DKIM_STAT_OK)
        << "dkim_chunk error: " << dkim_getresultstr(status_);
  }

  void foreach_sig(std::function<void(char const* domain, bool passed)> func)
  {
    int nsigs = 0;
    DKIM_SIGINFO** sigs;
    status_ = dkim_getsiglist(dkim_, &sigs, &nsigs);
    if (status_ == DKIM_STAT_INVALID) {
      LOG(WARNING) << "skipping DKIM sigs";
      return;
    }
    CHECK_EQ(status_, DKIM_STAT_OK);

    LOG(INFO) << "nsigs == " << nsigs;
    for (auto i = 0; i < nsigs; ++i) {
      auto dom = dkim_sig_getdomain(sigs[i]);
      CHECK_NOTNULL(dom);
      LOG(INFO) << "dom == " << dom;
      auto flg = dkim_sig_getflags(sigs[i]);

      if ((flg & DKIM_SIGFLAG_IGNORE) == DKIM_SIGFLAG_IGNORE) {
        LOG(INFO) << "ignoring sig for " << dom;
        continue;
      }
      if ((flg & DKIM_SIGFLAG_TESTKEY) == DKIM_SIGFLAG_TESTKEY) {
        LOG(INFO) << "testkey";
      }

      CHECK((flg & DKIM_SIGFLAG_PROCESSED) == DKIM_SIGFLAG_PROCESSED)
          << "sig for " << dom << " not processed";

      auto passed = (flg & DKIM_SIGFLAG_PASSED) == DKIM_SIGFLAG_PASSED;

      func(reinterpret_cast<char const*>(dom), passed);
    }
  }

  bool check()
  {
    int nsigs = 0;
    DKIM_SIGINFO** sigs;
    status_ = dkim_getsiglist(dkim_, &sigs, &nsigs);
    CHECK_EQ(status_, DKIM_STAT_OK);

    LOG(INFO) << "nsigs == " << nsigs;

    for (auto i = 0; i < nsigs; ++i) {
      LOG(INFO) << i << " domain == " << dkim_sig_getdomain(sigs[i]);
      auto flg = dkim_sig_getflags(sigs[i]);
      if ((flg & DKIM_SIGFLAG_IGNORE) == DKIM_SIGFLAG_IGNORE) {
        LOG(INFO) << "DKIM_SIGFLAG_IGNORE";
      }
      if ((flg & DKIM_SIGFLAG_PROCESSED) == DKIM_SIGFLAG_PROCESSED) {
        LOG(INFO) << "DKIM_SIGFLAG_PROCESSED";
      }
      if ((flg & DKIM_SIGFLAG_PASSED) == DKIM_SIGFLAG_PASSED) {
        LOG(INFO) << "DKIM_SIGFLAG_PASSED";
      }
      if ((flg & DKIM_SIGFLAG_TESTKEY) == DKIM_SIGFLAG_TESTKEY) {
        LOG(INFO) << "DKIM_SIGFLAG_TESTKEY";
      }
      if ((flg & DKIM_SIGFLAG_NOSUBDOMAIN) == DKIM_SIGFLAG_NOSUBDOMAIN) {
        LOG(INFO) << "DKIM_SIGFLAG_NOSUBDOMAIN";
      }
    }

    if (nsigs) {
      auto sig = dkim_getsignature(dkim_);
      if (sig) {

        LOG(INFO) << "dkim_getsignature domain == " << dkim_sig_getdomain(sig);

        ssize_t msglen;
        ssize_t canonlen;
        ssize_t signlen;

        status_
            = dkim_sig_getcanonlen(dkim_, sig, &msglen, &canonlen, &signlen);

        CHECK_EQ(status_, DKIM_STAT_OK);

        LOG(INFO) << "msglen == " << msglen;
        LOG(INFO) << "canonlen == " << canonlen;
        LOG(INFO) << "signlen == " << signlen;

        u_int nhdrs = 0u;
        status_ = dkim_sig_getsignedhdrs(dkim_, sig, nullptr, 0, &nhdrs);
        if (status_ != DKIM_STAT_NORESOURCE) {
          return false;
        }

        LOG(INFO) << "nhdrs == " << nhdrs;

        constexpr auto hdr_sz = DKIM_MAXHEADER + 1;
        std::vector<unsigned char> signedhdrs(nhdrs * hdr_sz, '\0');

        status_ = dkim_sig_getsignedhdrs(dkim_, sig, &signedhdrs[0], hdr_sz,
                                         &nhdrs);
        CHECK_EQ(status_, DKIM_STAT_OK);

        for (auto i = 0u; i < nhdrs; ++i)
          LOG(INFO) << &signedhdrs[i * hdr_sz];

        return true;
      }
    }

    return false;
  }

  bool check_signature(std::experimental::string_view str)
  {
    return dkim_sig_syntax(dkim_, uc(str.data()), str.length()) == DKIM_STAT_OK;
  }

private:
  DKIM* dkim_{nullptr};
  DKIM_STAT status_{DKIM_STAT_OK};
};
}

#endif // DKIM_DOT_HPP
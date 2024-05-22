#define _Bool bool
#include "OpenARC.hpp"

#include <regex>

#include <stdbool.h> // needs to be above <openarc/arc.h>

#include <openarc/arc.h>

#include "iobuffer.hpp"

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <glog/logging.h>

namespace {
u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>(cp));
}

char const* c(u_char* ucp) { return reinterpret_cast<char const*>(ucp); }
} // namespace

OpenARC::lib::lib()
{
  arc_ = arc_init();
  CHECK_NOTNULL(arc_);

  uint32_t arcl_flags;
  get_option(ARC_OPTS_FLAGS, &arcl_flags, sizeof(arcl_flags));
  arcl_flags |= ARC_LIBFLAGS_FIXCRLF;
  set_option(ARC_OPTS_FLAGS, &arcl_flags, sizeof(arcl_flags));

  char const* signhdrs[] = {"cc",
                            "content-language",
                            "content-transfer-encoding",
                            "content-type",
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

  set_option(ARC_OPTS_SIGNHDRS, signhdrs, sizeof(char**));

  char const* oversignhdrs[] = {"from", nullptr};
  set_option(ARC_OPTS_OVERSIGNHDRS, oversignhdrs, sizeof(char**));
}

OpenARC::lib::~lib()
{
  set_option(ARC_OPTS_SIGNHDRS, nullptr, sizeof(char**));
  set_option(ARC_OPTS_OVERSIGNHDRS, nullptr, sizeof(char**));

  arc_close(arc_);
}

void OpenARC::lib::get_option(int arg, void* val, size_t valsz)
{
  CHECK_EQ(arc_options(arc_, ARC_OP_GETOPT, arg, val, valsz), ARC_STAT_OK);
}

void OpenARC::lib::set_option(int arg, void* val, size_t valsz)
{
  CHECK_EQ(arc_options(arc_, ARC_OP_SETOPT, arg, val, valsz), ARC_STAT_OK);
}

void OpenARC::lib::set_cv_unkn() { arc_set_cv(msg_, ARC_CHAIN_UNKNOWN); }
void OpenARC::lib::set_cv_none() { arc_set_cv(msg_, ARC_CHAIN_NONE); }
void OpenARC::lib::set_cv_fail() { arc_set_cv(msg_, ARC_CHAIN_FAIL); }
void OpenARC::lib::set_cv_pass() { arc_set_cv(msg_, ARC_CHAIN_PASS); }

void OpenARC::lib::header(std::string_view header)
{
  CHECK_EQ(arc_header_field(msg_, uc(header.data()), header.length()),
           ARC_STAT_OK);
}

void OpenARC::lib::eoh() { CHECK_EQ(arc_eoh(msg_), ARC_STAT_OK); }

void OpenARC::lib::body(std::string_view body)
{
  CHECK_EQ(arc_body(msg_, uc(body.data()), body.length()), ARC_STAT_OK);
}

void OpenARC::lib::eom() { CHECK_EQ(arc_eom(msg_), ARC_STAT_OK); }

OpenARC::sign::sign()
{
  u_char const* error;
  msg_ = arc_message(arc_, ARC_CANON_RELAXED, ARC_CANON_RELAXED,
                     ARC_SIGN_RSASHA256, ARC_MODE_SIGN, &error);
  CHECK_NOTNULL(msg_);
}

OpenARC::sign::~sign() { arc_free(msg_); }

bool OpenARC::sign::seal(char const* authservid,
                         char const* selector,
                         char const* domain,
                         char const* key,
                         size_t      keylen,
                         char const* ar)
{
  // clang-format off
  auto const stat = arc_getseal(msg_,
                                &seal_,
                                const_cast<char*>(authservid),
                                const_cast<char*>(selector),
                                const_cast<char*>(domain),
                                uc(key),
                                keylen,
                                uc(ar));
  // clang-format on

  return stat == ARC_STAT_OK;
}

static std::string get_name(arc_hdrfield* hdr)
{
  CHECK_NOTNULL(hdr);
  size_t     len = 0;
  auto const p   = c(arc_hdr_name(hdr, &len));
  return std::string(p, len);
}

static std::string get_value(arc_hdrfield* hdr)
{
  CHECK_NOTNULL(hdr);
  auto const p = c(arc_hdr_value(hdr));
  return std::string(p, strlen(p));
}

std::string OpenARC::sign::name() const { return get_name(seal_); }

std::string OpenARC::sign::value() const { return get_value(seal_); }

std::vector<std::string> OpenARC::sign::whole_seal() const
{
  std::vector<std::string> hdrs;

  auto const re = std::regex("(?:\\r\\n|\\n|\\r)");
  for (auto sealhdr = seal_; sealhdr; sealhdr = arc_hdr_next(sealhdr)) {
    auto const hdr =
        fmt::format("{}:{}", get_name(sealhdr), get_value(sealhdr));
    hdrs.emplace_back(std::regex_replace(hdr, re, "\r\n"));
  }

  return hdrs;
}

OpenARC::verify::verify()
{
  u_char const* error;
  msg_ = arc_message(arc_, ARC_CANON_RELAXED, ARC_CANON_RELAXED,
                     ARC_SIGN_RSASHA256, ARC_MODE_VERIFY, &error);
  CHECK_NOTNULL(msg_);
}

OpenARC::verify::~verify() { arc_free(msg_); }

char const* OpenARC::verify::chain_status_str() const
{
  return arc_chain_status_str(msg_);
}

std::string OpenARC::verify::chain_custody_str() const
{
  for (iobuffer<char> buf{256}; buf.size() < 10 * 1024 * 1024;
       buf.resize(buf.size() * 2)) {
    size_t len = arc_chain_custody_str(msg_, uc(buf.data()), buf.size());
    if (len < buf.size())
      return std::string(buf.data(), len);
  }
  LOG(FATAL) << "custody chain way too large...";
  return "";
}

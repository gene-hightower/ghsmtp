#include "OpenARC.hpp"

#include <stdbool.h> // needs to be above <openarc/arc.h>

#include <openarc/arc.h>

#include "iobuffer.hpp"

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
}

OpenARC::lib::~lib() { arc_close(arc_); }

void OpenARC::lib::get_option(int arg, void* val, size_t valsz)
{
  CHECK_EQ(arc_options(arc_, ARC_OP_GETOPT, arg, val, valsz), ARC_STAT_OK);
}

void OpenARC::lib::set_option(int arg, void* val, size_t valsz)
{
  CHECK_EQ(arc_options(arc_, ARC_OP_SETOPT, arg, val, valsz), ARC_STAT_OK);
}

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
  msg_ = arc_message(arc_, ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
                     ARC_SIGN_RSASHA256, ARC_MODE_SIGN, &error);
  CHECK_NOTNULL(msg_);
}

OpenARC::sign::~sign() { arc_free(msg_); }

void OpenARC::sign::seal(ARC_HDRFIELD** seal,
                         char const*    authservid,
                         char const*    selector,
                         char const*    domain,
                         char const*    key,
                         size_t         keylen,
                         char const*    ar)
{
  CHECK_EQ(arc_getseal(msg_, seal, const_cast<char*>(authservid),
                       const_cast<char*>(selector), const_cast<char*>(domain),
                       uc(key), keylen, uc(ar)),
           ARC_STAT_OK);
}

OpenARC::verify::verify()
{
  u_char const* error;
  msg_ = arc_message(arc_, ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
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

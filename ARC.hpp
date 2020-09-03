#ifndef ARC_DOT_HPP_INCLUDED
#define ARC_DOT_HPP_INCLUDED

#include "iobuffer.hpp"

#include <cstring>

#include <stdbool.h> // needs to be above <openarc/arc.h>

#include <openarc/arc.h>

#include <glog/logging.h>

namespace ARC {

u_char* uc(char const* cp)
{
  return reinterpret_cast<u_char*>(const_cast<char*>(cp));
}

char const* c(u_char* ucp) { return reinterpret_cast<char const*>(ucp); }

namespace hdr {
std::string_view name(ARC_HDRFIELD* hp)
{
  size_t     sz;
  auto const nm = c(arc_hdr_name(hp, &sz));
  return {nm, sz};
}

std::string_view value(ARC_HDRFIELD* hp)
{
  auto const nm = c(arc_hdr_value(hp));
  return {nm, strlen(nm)};
}
} // namespace hdr

class msg {
public:
  // move, no copy
  msg(msg&&)   = default;
  msg& operator=(msg&&) = default;

  msg(ARC_MESSAGE* msg)
    : msg_(msg)
  {
    CHECK_NOTNULL(msg_);
  }
  ~msg() { arc_free(msg_); }

  ARC_STAT header_field(char const* hname, size_t hlen)
  {
    return arc_header_field(msg_, uc(hname), hlen);
  }
  ARC_STAT eoh() { return arc_eoh(msg_); }
  ARC_STAT body(char const* buf, size_t len)
  {
    return arc_body(msg_, uc(buf), len);
  }
  ARC_STAT eom() { return arc_eom(msg_); }

  char const* chain_status_str() { return arc_chain_status_str(msg_); }

  std::string chain_custody_str()
  {
    for (iobuffer<char> buf{256}; buf.size() < 10 * 1024 * 1024;
         buf.resize(buf.size() * 2)) {
      size_t len = arc_chain_custody_str(msg_, uc(buf.data()), buf.size());
      if (len < buf.size())
        return std::string(buf.data(), len);
    }
    LOG(FATAL) << "custody chain way too large...";
  }

  ARC_STAT seal(ARC_HDRFIELD** seal,
                char const*    authservid,
                char const*    selector,
                char const*    domain,
                char const*    key,
                size_t         keylen,
                char const*    ar)
  {
    return arc_getseal(msg_, seal, const_cast<char*>(authservid),
                       const_cast<char*>(selector), const_cast<char*>(domain),
                       uc(key), keylen, uc(ar));
  }

  char const* geterror() const { return arc_geterror(msg_); }

private:
  ARC_MESSAGE* msg_;
};

class lib {
public:
  // move, no copy
  lib(lib&&)   = default;
  lib& operator=(lib&&) = default;

  lib()
    : arc_(arc_init())
  {
    CHECK_NOTNULL(arc_);
  }
  ~lib() { arc_close(arc_); }

  char const* geterror(ARC_MESSAGE* msg) { return arc_geterror(msg); }

  ARC_STAT get_option(int arg, void* val = nullptr, size_t valsz = 0)
  {
    return arc_options(arc_, ARC_OP_GETOPT, arg, val, valsz);
  }
  ARC_STAT set_option(int arg, void* val = nullptr, size_t valsz = 0)
  {
    return arc_options(arc_, ARC_OP_SETOPT, arg, val, valsz);
  }

  msg message(arc_canon_t  canonhdr,
              arc_canon_t  canonbody,
              arc_alg_t    signalg,
              arc_mode_t   mode,
              char const** error)
  {
    return msg(arc_message(arc_, canonhdr, canonbody, signalg, mode,
                           reinterpret_cast<u_char const**>(error)));
  }

private:
  ARC_LIB* arc_;
};

} // namespace ARC

#endif // ARC_DOT_HPP_INCLUDED

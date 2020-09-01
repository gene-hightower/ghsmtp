#ifndef ARC_DOT_HPP_INCLUDED
#define ARC_DOT_HPP_INCLUDED

#include <stdbool.h>

#include <openarc/arc.h>

namespace ARC {

u_char* uc(char const* p)
{
  return reinterpret_cast<u_char*>(const_cast<char*>(p));
}

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
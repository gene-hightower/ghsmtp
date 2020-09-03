#ifndef OPENARC_DOT_HPP_INCLUDED
#define OPENARC_DOT_HPP_INCLUDED

#include <cstring>
#include <string_view>

// Forward to keep from including <openarc/arc.h>
struct arc_hdrfield;
struct arc_lib;
struct arc_msghandle;

namespace OpenARC {

class lib {
  // no copy
  lib(lib const&) = delete;
  lib& operator=(lib const&) = delete;

public:
  // move
  lib(lib&&)   = default;
  lib& operator=(lib&&) = default;

  void get_option(int arg, void* val = nullptr, size_t valsz = 0);
  void set_option(int arg, void* val = nullptr, size_t valsz = 0);

  void header(std::string_view header);
  void eoh();
  void body(std::string_view body);
  void chunk(std::string_view chunk);
  void eom();

protected:
  lib();
  ~lib();

  arc_lib*       arc_ = nullptr;
  arc_msghandle* msg_ = nullptr;
};

class sign : public lib {
public:
  sign();
  ~sign();

  void seal(arc_hdrfield** seal,
            char const*    authservid,
            char const*    selector,
            char const*    domain,
            char const*    key,
            size_t         keylen,
            char const*    ar);
};

class verify : public lib {
public:
  verify();
  ~verify();

  char const* chain_status_str() const;
  std::string chain_custody_str() const;
};

} // namespace OpenARC

#endif // OPENARC_DOT_HPP_INCLUDED

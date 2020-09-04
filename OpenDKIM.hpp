#ifndef OPENDKIM_DOT_HPP
#define OPENDKIM_DOT_HPP

#include <functional>
#include <string>
#include <string_view>

struct dkim_lib;
struct dkim;

namespace OpenDKIM {

class lib {
  // no copy
  lib(lib const&) = delete;
  lib& operator=(lib const&) = delete;

  // move
  lib(lib&&)   = default;
  lib& operator=(lib&&) = default;

public:
  void header(std::string_view header);
  void eoh();
  void body(std::string_view body);
  void chunk(std::string_view chunk);
  void eom();

protected:
  lib();
  ~lib();

  dkim_lib* lib_{nullptr};
  dkim*     dkim_{nullptr};
  int       status_{0};
};

class sign : public lib {
public:
  enum class body_type : bool {
    binary,
    text,
  };

  sign(char const* secretkey,
       char const* selector,
       char const* domain,
       body_type   typ = body_type::text);

  std::string getsighdr();
};

class verify : public lib {
public:
  verify();

  bool check();
  bool sig_syntax(std::string_view sig);
  void foreach_sig(std::function<void(char const* domain,
                                      bool        passed,
                                      char const* identity,
                                      char const* selector,
                                      char const* b)> func);
};

} // namespace OpenDKIM

#endif // OPENDKIM_DOT_HPP

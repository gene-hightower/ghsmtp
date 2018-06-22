#ifndef DKIM_DOT_HPP
#define DKIM_DOT_HPP

#include <functional>
#include <string_view>

typedef struct dkim_lib DKIM_LIB; // local or forward declaration
typedef struct dkim DKIM;         // local or forward declaration
typedef int DKIM_STAT;            // local or forward declaration

namespace OpenDKIM {

class Lib {
  Lib(Lib const&) = delete;
  Lib& operator=(Lib const&) = delete;

public:
  void header(std::string_view header);
  void eoh();
  void body(std::string_view body);
  void chunk(std::string_view chunk);
  void eom();

protected:
  Lib();
  ~Lib();

  DKIM_LIB* lib_{nullptr};
  DKIM* dkim_{nullptr};
  DKIM_STAT status_{0};
};

class Verify : public Lib {
public:
  Verify();

  bool check();
  bool sig_syntax(std::string_view sig);
  void foreach_sig(std::function<void(char const* domain, bool passed)> func);
};

class Sign : public Lib {
public:
  enum class body_type : bool {
    binary,
    text,
  };

  Sign(char const* secretkey,
       char const* selector,
       char const* domain,
       body_type typ = body_type::text);

  std::string getsighdr();
};
} // namespace OpenDKIM

#endif // DKIM_DOT_HPP

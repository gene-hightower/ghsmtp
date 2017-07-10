#ifndef DKIM_DOT_HPP
#define DKIM_DOT_HPP

#include <functional>

#include <experimental/string_view>

struct dkim_lib;
typedef struct dkim_lib DKIM_LIB;

struct dkim;
typedef struct dkim DKIM;

typedef int DKIM_STAT;

namespace OpenDKIM {

class Lib {
public:
  virtual ~Lib();

  void header(std::experimental::string_view header);
  void eoh();
  void body(std::experimental::string_view body);
  void chunk(std::experimental::string_view chunk);
  void eom();

protected:
  Lib();

  DKIM_LIB* lib_{nullptr};
  DKIM* dkim_{nullptr};
  DKIM_STAT status_{0};
};

class Verify : public Lib {
public:
  Verify();

  bool check();
  bool check_signature(std::experimental::string_view str);
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
}

#endif // DKIM_DOT_HPP

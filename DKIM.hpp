#ifndef DKIM_DOT_HPP
#define DKIM_DOT_HPP

#include <functional>
#include <string_view>

typedef struct dkim_lib DKIM_LIB;
typedef struct dkim DKIM;

typedef int DKIM_STAT;

namespace OpenDKIM {

class Lib {
  Lib(Lib const&) = delete;
  Lib& operator=(Lib const&) = delete;

public:
  auto header(std::string_view header) -> void;
  auto eoh() -> void;
  auto body(std::string_view body) -> void;
  auto chunk(std::string_view chunk) -> void;
  auto eom() -> void;

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

  auto check() -> bool;
  auto sig_syntax(std::string_view sig) -> bool;
  auto foreach_sig(std::function<void(char const* domain, bool passed)> func)
      -> void;
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

  auto getsighdr() -> std::string;
};
} // namespace OpenDKIM

#endif // DKIM_DOT_HPP

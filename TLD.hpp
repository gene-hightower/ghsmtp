#ifndef TLD_DOT_HPP
#define TLD_DOT_HPP

#include <glog/logging.h>

extern "C" {
#include <libpsl.h>
}

class TLD {
public:
  TLD(TLD const&) = delete;
  TLD& operator=(TLD const&) = delete;

  TLD()
    : ctx_(CHECK_NOTNULL(psl_latest(nullptr)))
  {
  }
  ~TLD() { psl_free(ctx_); }

  char const* get_registered_domain(char const* dom) const
  {
    return psl_registrable_domain(ctx_, dom);
  }

  char const* get_registered_domain(std::string const& dom) const
  {
    return get_registered_domain(dom.c_str());
  }

private:
  psl_ctx_t* ctx_;
};

#endif // TLD_DOT_HPP

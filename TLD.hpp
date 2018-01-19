#ifndef TLD_DOT_HPP
#define TLD_DOT_HPP

#include <glog/logging.h>

extern "C" {
#include <regdom.h>
}

class TLD {
public:
  TLD(TLD const&) = delete;
  TLD& operator=(TLD const&) = delete;

  TLD()
    : tree_(CHECK_NOTNULL(loadTldTree()))
  {
  }
  ~TLD() { freeTldTree(tree_); }

  char const* get_registered_domain(char const* dom) const
  {
    return getRegisteredDomain(dom, tree_);
  }

  char const* get_registered_domain(std::string const& dom) const
  {
    return get_registered_domain(dom.c_str());
  }

private:
  void* tree_;
};

#endif // TLD_DOT_HPP

#ifndef IOBUFFER_DOT_HPP
#define IOBUFFER_DOT_HPP

#include "default_init_allocator.hpp"

#include <cstddef>
#include <vector>

template <typename ByteT = std::byte>
class iobuffer {
public:
  using buffer_t  = std::vector<ByteT, default_init_allocator<ByteT>>;
  using size_type = typename buffer_t::size_type;

  iobuffer() = default;
  explicit iobuffer(size_type sz)
    : buf_(sz)
  {
  }

  auto data() { return buf_.data(); }
  auto data() const { return buf_.data(); }
  auto size() const { return buf_.size(); }
  auto resize(size_type sz) { return buf_.resize(sz); }
  void shrink_to_fit() { buf_.shrink_to_fit(); }

  auto begin() const { return buf_.begin(); }
  auto end() const { return buf_.end(); }

  bool operator==(iobuffer const& rhs) const
  {
    if (this->size() == rhs.size())
      return memcmp(this->data(), rhs.data(), this->size()) == 0;
    return false;
  }

  bool operator<(iobuffer const& rhs) const
  {
    if (this->size() == rhs.size())
      return memcmp(this->data(), rhs.data(), this->size()) < 0;
    return this->size() < rhs.size();
  }

private:
  buffer_t buf_;
};

#endif // IOBUFFER_DOT_HPP

#ifndef DEFAULT_INIT_ALLOCATOR_DOT_HPP
#define DEFAULT_INIT_ALLOCATOR_DOT_HPP

// Allocator adaptor that interposes construct() calls to convert
// value initialization into default initialization.

// This is Casey's allocator adaptor from SO. See:
// <https://stackoverflow.com/a/21028912/273767>
// <https://en.cppreference.com/w/cpp/container/vector/resize>

#include <memory>

template <typename T, typename A = std::allocator<T>>
class default_init_allocator : public A {
  typedef std::allocator_traits<A> a_t;

public:
  template <typename U>
  struct rebind {
    using other =
        default_init_allocator<U, typename a_t::template rebind_alloc<U>>;
  };

  using A::A;

  template <typename U>
  void
  construct(U* ptr) noexcept(std::is_nothrow_default_constructible<U>::value)
  {
    ::new (static_cast<void*>(ptr)) U;
  }
  template <typename U, typename... Args>
  void construct(U* ptr, Args&&... args)
  {
    a_t::construct(static_cast<A&>(*this), ptr, std::forward<Args>(args)...);
  }
};

#endif // DEFAULT_INIT_ALLOCATOR_DOT_HPP

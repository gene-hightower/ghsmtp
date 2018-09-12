#include "default_init_allocator.hpp"

#include <iostream>
#include <vector>

#include <glog/logging.h>

int main()
{
  std::vector<int, default_init_allocator<int>> v;

  // fill v with values [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  v.resize(10);
  for (size_t i = 0; i < 10; ++i)
    v[i] = i;

  // chop off the end of v, which now should be [1, 2, 3, 4, 5], but
  // the other 5 values should remain in memory
  v.resize(5);

  // grow back to 10
  v.resize(10);

  for (size_t i = 0; i < v.size(); ++i) {
    CHECK_EQ(v[i], i);
  }
}

#include "iobuffer.hpp"

#include <glog/logging.h>

int main()
{
  iobuffer<char> v;

  // fill v with values [0..9]
  v.resize(10);
  for (size_t i = 0; i < 10; ++i)
    *(v.data() + i) = i;

  // chop off the end of v, which now should be [0..4], but
  // the other 5 values should remain in memory
  v.resize(5);

  // grow back to 10
  v.resize(10);

  // verify the values are unchanged
  CHECK_EQ(v.size(), 10);
  for (size_t i = 0; i < 10; ++i) {
    CHECK_EQ(*(v.data() + i), i);
  }
}

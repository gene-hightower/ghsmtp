#include "iobuffer.hpp"

#include <glog/logging.h>

const auto N = 100'000;

int main()
{
  iobuffer<char> v;

  // fill v with values [0..N-1]
  v.resize(N);
  for (size_t i = 0; i < N; ++i)
    *(v.data() + i) = i & 0x7F;

  // chop off the end of v, which now should be [0..N/2], but
  // the other N/2 values should remain in memory
  v.resize(N / 2);

  // grow back to N
  v.resize(N);

  // verify the values are unchanged
  CHECK_EQ(v.size(), N);
  for (size_t i = 0; i < N; ++i) {
    CHECK_EQ(*(v.data() + i), i & 0x7F);
  }

  iobuffer<char> q(std::move(v));

  CHECK_EQ(q.size(), N);
  for (size_t i = 0; i < N; ++i) {
    CHECK_EQ(*(q.data() + i), i & 0x7F);
  }

  iobuffer<char> qq(std::move(q));

  CHECK_EQ(qq.size(), N);
  for (size_t i = 0; i < N; ++i) {
    CHECK_EQ(*(qq.data() + i), i & 0x7F);
  }

  iobuffer<char> qqq(std::move(qq));

  CHECK_EQ(qqq.size(), N);
  for (size_t i = 0; i < N; ++i) {
    CHECK_EQ(*(qqq.data() + i), i & 0x7F);
  }
}

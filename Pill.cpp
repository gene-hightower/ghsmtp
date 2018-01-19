#include "Pill.hpp"

#include <random>

#include <boost/config.hpp>

Pill::Pill()
{
  auto rd{std::random_device{}};
  auto uni_dist{std::uniform_int_distribution<decltype(s_)>{}};

  s_ = uni_dist(rd);

  auto resp{b32_ndigits_};
  b32_str_[resp] = '\0';

  // <http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt>

  constexpr char b32_charset[]{"ybndrfg8ejkmcpqxot1uwisza345h769"};

  auto const os = reinterpret_cast<const unsigned char*>(&s_);
  auto osp = os + sizeof(s_);
  auto x{0ul};

  switch ((osp - os) % 5) { // Duff's device
  case 0:
    do {
      x = *--osp;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      [[fallthrough]];

    case 4:
      x |= (static_cast<unsigned long>(*--osp)) << 3;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      [[fallthrough]];

    case 3:
      x |= (static_cast<unsigned long>(*--osp)) << 1;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      [[fallthrough]];

    case 2:
      x |= (static_cast<unsigned long>(*--osp)) << 4;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      [[fallthrough]];

    case 1:
      x |= (static_cast<unsigned long>(*--osp)) << 2;
      b32_str_[--resp] = b32_charset[x % 32];
      x /= 32;
      b32_str_[--resp] = b32_charset[x];
    } while (osp > os);
  }
}

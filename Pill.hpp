/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
*/

#ifndef PILL_DOT_HPP
#define PILL_DOT_HPP

#include <climits>
#include <cstdio>
#include <iostream>
#include <random>

#include <glog/logging.h>

// A pill is a unit of entropy.

class Pill {
public:
  Pill()
  {
    std::random_device rd;
    std::uniform_int_distribution<decltype(s_)> uni_dist;

    s_ = uni_dist(rd);

    int resp = b32_ndigits_;
    b32_str_[resp] = '\0';

    // <http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt>

    static constexpr const char* const b32_charset
        = "ybndrfg8ejkmcpqxot1uwisza345h769";

    const unsigned char* os = reinterpret_cast<const unsigned char*>(&s_);
    const unsigned char* osp = os + sizeof(s_);

    unsigned long x = 0;

    switch ((osp - os) % 5) {
    case 0:
      do {
        x = *--osp;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
      case 4:
        x |= (static_cast<unsigned long>(*--osp)) << 3;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
      case 3:
        x |= (static_cast<unsigned long>(*--osp)) << 1;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
      case 2:
        x |= (static_cast<unsigned long>(*--osp)) << 4;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
      case 1:
        x |= (static_cast<unsigned long>(*--osp)) << 2;
        b32_str_[--resp] = b32_charset[x % 32];
        x /= 32;
        b32_str_[--resp] = b32_charset[x];
      } while (osp > os);
    }
  }
  bool operator==(Pill const& that) const { return this->s_ == that.s_; }
  bool operator!=(Pill const& that) const { return !(*this == that); }

private:
  unsigned long long s_;

  static constexpr int b32_ndigits_ = ((sizeof(s_) * CHAR_BIT) + 4) / 5;
  char b32_str_[b32_ndigits_ + 1];

  friend std::ostream& operator<<(std::ostream& s, Pill const& p)
  {
    return s << p.b32_str_;
  }
};

#endif // PILL_DOT_HPP

/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TLD_DOT_H
#define TLD_DOT_H

#include "Logging.hpp"

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

  char const* get_registered_domain(char const* dom)
  {
    return getRegisteredDomain(dom, tree_);
  }

private:
  void* tree_;
};

#endif // TLD_DOT_H

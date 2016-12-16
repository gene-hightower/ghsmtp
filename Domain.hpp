/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2014  Gene Hightower <gene@digilicious.com>
*/

#ifndef DOMAIN_DOT_HPP
#define DOMAIN_DOT_HPP

#include <boost/algorithm/string/predicate.hpp>
#include <experimental/string_view>

namespace Domain {

inline bool match(std::experimental::string_view a,
                  std::experimental::string_view b)
{
  if ((0 != a.length()) && ('.' == a.back())) {
    a.remove_suffix(1);
  }

  if ((0 != b.length()) && ('.' == b.back())) {
    b.remove_suffix(1);
  }

  return boost::iequals(a, b);
}
}

#endif // DOMAIN_DOT_HPP

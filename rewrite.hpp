#ifndef REWRITE_DOT_HPP_INCLUDED
#define REWRITE_DOT_HPP_INCLUDED

#include <memory>
#include <utility>

std::pair<std::unique_ptr<char[]>, size_t> rewrite(char const* dp_in,
                                                   size_t      length_in);
#endif // REWRITE_DOT_HPP_INCLUDED

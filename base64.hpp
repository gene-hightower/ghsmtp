#ifndef BASE64_H
#define BASE64_H

#include <string>

#include <experimental/string_view>

namespace Base64 {
std::string enc(std::experimental::string_view in, bool wrap = false);
std::string dec(std::experimental::string_view in);
}

#endif // BASE64_H
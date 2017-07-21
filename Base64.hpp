#ifndef BASE64_H
#define BASE64_H

#include <experimental/string_view>
#include <string>

namespace Base64 {
std::string enc(std::experimental::string_view in,
                std::string::size_type wrap = 0);
std::string dec(std::experimental::string_view in);
}

#endif // BASE64_H

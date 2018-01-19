#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <string_view>

namespace Base64 {
std::string enc(std::string_view in, std::string::size_type wrap = 0);
std::string dec(std::string_view in);
} // namespace Base64

#endif // BASE64_H

#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <string_view>

namespace Base64 {
auto enc(std::string_view in, std::string::size_type wrap = 0) -> std::string;
auto dec(std::string_view in) -> std::string;
} // namespace Base64

#endif // BASE64_H

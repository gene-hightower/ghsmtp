#ifndef MESSAGE_DOT_HPP_INCLUDED
#define MESSAGE_DOT_HPP_INCLUDED

#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "fs.hpp"
#include "iequal.hpp"

namespace message {
struct header {
  header(std::string_view n, std::string_view v)
    : name(n)
    , value(v)
  {
  }

  std::string as_string() const;

  std::string_view as_view() const
  {
    return {name.begin(),
            static_cast<size_t>(std::distance(name.begin(), value.end()))};
  }

  bool operator==(std::string_view n) const { return iequal(n, name); }

  std::string_view name;
  std::string_view value;
}; // namespace header

struct parsed {
  bool parse(std::string_view input);
  bool parse_hdr(std::string_view input);

  std::string as_string() const;

  bool write(std::ostream& out) const;

  std::vector<header> headers;

  std::string_view field_name;
  std::string_view field_value;

  std::string_view body;

  // New Authentication_Results field
  std::string ar_str;

  // New DKIM-Signature that includes above AR
  std::string sig_str;

  std::vector<std::string> arc_hdrs;
};

parsed authentication(fs::path         config_path,
                      char const*      domain,
                      std::string_view input);

void dkim_check(fs::path         config_path,
                char const*      domain,
                std::string_view input);

parsed
rewrite(fs::path config_path, char const* domain, std::string_view input);

void print_spf_envelope_froms(char const* domain, std::string_view input);

} // namespace message

#endif // MESSAGE_DOT_HPP_INCLUDED

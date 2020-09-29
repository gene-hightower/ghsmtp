#ifndef MESSAGE_DOT_HPP_INCLUDED
#define MESSAGE_DOT_HPP_INCLUDED

#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "Mailbox.hpp"
#include "fs.hpp"
#include "iequal.hpp"

namespace message {

// RFC-5322 header names
auto constexpr ARC_Authentication_Results = "ARC-Authentication-Results";
auto constexpr ARC_Message_Signature      = "ARC-Message-Signature";
auto constexpr ARC_Seal                   = "ARC-Seal";

auto constexpr Authentication_Results = "Authentication-Results";
auto constexpr DKIM_Signature         = "DKIM-Signature";
auto constexpr Delivered_To           = "Delivered-To";
auto constexpr From                   = "From";
auto constexpr In_Reply_To            = "In-Reply-To";
auto constexpr Received_SPF           = "Received-SPF";
auto constexpr Reply_To               = "Reply-To";
auto constexpr Return_Path            = "Return-Path";
auto constexpr Subject                = "Subject";

// MIME headers
auto constexpr Content_Type = "Content-Type";
auto constexpr MIME_Version = "MIME-Version";

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

struct name_addr {
  std::string name;
  std::string addr;
};

struct mailbox_name_addr_list {
  std::string            name;
  std::vector<name_addr> name_addr_list;
};

struct parsed {
  bool parse(std::string_view input);
  bool parse_hdr(std::string_view input);

  std::string as_string() const;

  bool write(std::ostream& out) const;

  std::vector<header> headers;

  std::string_view get_header(std::string_view hdr) const;

  std::string_view field_name;
  std::string_view field_value;

  std::string_view body;

  // Parsing of the RFC-5322.From header
  mailbox_name_addr_list from_parsed;
  std::string            dmarc_from;
  std::string            dmarc_from_domain;

  // RFC5322.Reply
  std::string reply_to_str;

  // New RFC5322.From
  std::string from_str;

  // New body
  std::string body_str;

  // New Authentication_Results field
  std::string ar_str;

  // New DKIM-Signature that includes above AR
  std::string sig_str;

  // Added ARC headers
  std::vector<std::string> arc_hdrs;
};

bool authentication_reaults_parse(std::string_view input,
                                  std::string&     authservid);

bool authentication(message::parsed& msg,
                    char const*      sender,
                    char const*      selector,
                    fs::path         key_file);

void dkim_check(message::parsed& msg, char const* domain);

void remove_delivery_headers(message::parsed& msg);

void dkim_sign(message::parsed& msg,
               char const*      sender,
               char const*      selector,
               fs::path         key_file);

void rewrite(message::parsed& msg,
             std::string      mail_from,
             std::string      reply_to,
             char const*      sender,
             char const*      selector,
             fs::path         key_file);

void print_spf_envelope_froms(char const* domain, message::parsed& msg);

} // namespace message

#endif // MESSAGE_DOT_HPP_INCLUDED

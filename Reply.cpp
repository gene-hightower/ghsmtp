#include "Reply.hpp"

#include "Hash.hpp"
#include "Mailbox.hpp"
#include "iequal.hpp"
#include "is_ascii.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <string>

#include <cppcodec/base32_crockford.hpp>

#include <arpa/inet.h>
#include <time.h>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

using std::begin;
using std::end;

constexpr int hash_length_min = 6; // 1 in a billion
constexpr int hash_length_max = 10;

constexpr const char sep_chars_array[] = {
    '_',
    '=' // Must not be allowed in domain names, must not be in base32 alphabet.
};

constexpr std::string_view sep_chars{sep_chars_array, sizeof(sep_chars_array)};

constexpr std::string_view REP_PREFIX = "rep="; // legacy reply prefix

std::string to_lower(std::string data)
{
  std::transform(data.begin(), data.end(), data.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return data;
}

static std::string hash_rep(Reply::from_to const& rep, std::string_view secret)
{
  Hash h;
  h.update(secret);
  h.update(to_lower(rep.mail_from));
  h.update(to_lower(rep.rcpt_to_local_part));
  return to_lower(h.final().substr(0, hash_length_min));
}

std::string enc_reply_blob(Reply::from_to const& rep, std::string_view secret)
{
  auto const hash = hash_rep(rep, secret);

  auto const pkt = fmt::format("{}{}{}{}{}", // clang-format off
                               hash, '\0',
                               rep.rcpt_to_local_part, '\0',
                               rep.mail_from); // clang-format on

  return to_lower(cppcodec::base32_crockford::encode(pkt));
}

std::string Reply::enc_reply(Reply::from_to const& rep, std::string_view secret)
{
  auto const result = Mailbox::parse(rep.mail_from);
  if (!result) {
    throw std::invalid_argument("invalid mailbox syntax in enc_reply");
  }

  // If it's "local part"@example.com or local-part@[127.0.0.1] we
  // must fall back to the blob style.
  if (result->local_type == Mailbox::local_types::quoted_string ||
      result->domain_type == Mailbox::domain_types::address_literal) {
    return enc_reply_blob(rep, secret);
  }

  auto const rcpt_to =
      Mailbox::parse(fmt::format("{}@x.y", rep.rcpt_to_local_part));
  if (!rcpt_to) {
    throw std::invalid_argument("invalid local-part syntax in enc_reply");
  }
  if (rcpt_to->local_type == Mailbox::local_types::quoted_string) {
    return enc_reply_blob(rep, secret);
  }

  for (auto sep_char : sep_chars) {
    if (rep.rcpt_to_local_part.find(sep_char) == std::string_view::npos) {
      // Must never be in the domain part, that's crazy
      CHECK_EQ(result->domain.find(sep_char), std::string_view::npos);
      // The sep_char *can* be in the result->local part
      auto const hash_enc = hash_rep(rep, secret);
      return fmt::format("{}{}{}{}{}{}{}", // clang-format off
                         result->local, sep_char,
                         result->domain, sep_char,
                         rep.rcpt_to_local_part, sep_char,
                         hash_enc); // clang-format on
    }
  }

  return enc_reply_blob(rep, secret);
}

auto split(std::string const& str, const char delim)
{
  std::vector<std::string> out;

  size_t start;
  size_t end = 0;
  while ((start = str.find_first_not_of(delim, end)) != std::string::npos) {
    end = str.find(delim, start);
    out.push_back(str.substr(start, end - start));
  }

  return out;
}

static std::optional<Reply::from_to> dec_reply_blob(std::string_view addr,
                                                    std::string_view secret)
{
  auto const pktv = cppcodec::base32_crockford::decode(addr);
  auto const pkt =
      std::string(reinterpret_cast<char const*>(pktv.data()), pktv.size());

  auto const parts = split(pkt, '\0');

  if (parts.size() != 3) {
    LOG(WARNING) << "invalid blob format";
    return {};
  }

  auto const hash = parts[0];

  Reply::from_to rep;
  rep.rcpt_to_local_part = parts[1];
  rep.mail_from          = parts[2];

  auto const hash_computed = hash_rep(rep, secret);

  if (!iequal(hash_computed, hash)) {
    LOG(WARNING) << "hash check failed";
    return {};
  }

  return rep;
}

static bool is_pure_base32(std::string_view s)
{
  // clang-format off
  static constexpr const char base32_crockford_alphabet_i[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'J', 'K',
    'M', 'N',
    'P', 'Q', 'R', 'S', 'T',
    'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'j', 'k',
    'm', 'n',
    'p', 'q', 'r', 's', 't',
    'v', 'w', 'x', 'y', 'z'
  };
  // clang-format on

  auto constexpr alpha = std::string_view(base32_crockford_alphabet_i,
                                          sizeof(base32_crockford_alphabet_i));

  // If we can't find anything not in the base32 alphabet, it's pure
  return s.find_first_not_of(alpha) == std::string_view::npos;
}

std::optional<Reply::from_to>
try_decode(std::string_view addr, std::string_view secret, char sep_char)
{
  // {mail_from.local}={mail_from.domain}={rcpt_to_local_part}={hash}

  auto const hash_sep = addr.find_last_of(sep_char);
  if (hash_sep == std::string_view::npos)
    return {};
  auto const hash_pos = hash_sep + 1;
  auto const hash_len = addr.length() - hash_pos;
  if ((hash_len < hash_length_min) || (hash_len > hash_length_max))
    return {};
  auto const hash = addr.substr(hash_pos, hash_len);

  // The hash part must look like a hash
  if (!is_pure_base32(hash))
    return {};

  auto const rcpt_loc_sep = addr.substr(0, hash_sep).find_last_of(sep_char);
  if (rcpt_loc_sep == std::string_view::npos)
    return {};
  auto const rcpt_loc_pos = rcpt_loc_sep + 1;
  auto const rcpt_loc_len = hash_sep - rcpt_loc_pos;
  auto const rcpt_loc     = addr.substr(rcpt_loc_pos, rcpt_loc_len);

  auto const mail_from_dom_sep =
      addr.substr(0, rcpt_loc_sep).find_last_of(sep_char);
  if (mail_from_dom_sep == std::string_view::npos)
    return {};
  auto const mail_from_dom_pos = mail_from_dom_sep + 1;
  auto const mail_from_dom_len = rcpt_loc_sep - mail_from_dom_pos;
  auto const mail_from_dom = addr.substr(mail_from_dom_pos, mail_from_dom_len);

  auto const mail_from_loc = addr.substr(0, mail_from_dom_sep);
  auto const mail_from     = fmt::format("{}@{}", mail_from_loc, mail_from_dom);

  // The mail_from part must be a valid Mailbox address.
  if (!Mailbox::validate(mail_from))
    return {};

  Reply::from_to rep;
  rep.mail_from          = mail_from;
  rep.rcpt_to_local_part = rcpt_loc;

  auto const hash_computed = hash_rep(rep, secret);

  if (!iequal(hash_computed, hash)) {
    LOG(WARNING) << "hash check failed";
    return {};
  }

  return rep;
}

/*
 * Legacy format reply address with the REP= prefix. We no longer
 * generates these addresses, but we continue to decode them in a
 * compatable way.
 */

std::optional<Reply::from_to> old_dec_reply(std::string_view addr,
                                            std::string_view secret)
{
  addr.remove_prefix(REP_PREFIX.length());

  if (is_pure_base32(addr)) {
    // if everything after REP= is base32 we have a blob
    return dec_reply_blob(addr, secret);
  }

  // REP= has been removed, addr is now:
  // {hash}={rcpt_to_local_part}={mail_from.local}={mail_from.domain}
  //       ^1st                 ^2nd              ^last
  // and mail_from.local can contain '=' chars

  auto const first_sep  = addr.find_first_of('=');
  auto const last_sep   = addr.find_last_of('=');
  auto const second_sep = addr.find_first_of('=', first_sep + 1);

  if (first_sep == last_sep || second_sep == last_sep) {
    LOG(WARNING) << "unrecognized legacy reply format " << addr;
    return {};
  }

  auto const rcpt_to_pos = first_sep + 1;
  auto const mf_loc_pos  = second_sep + 1;
  auto const mf_dom_pos  = last_sep + 1;

  auto const rcpt_to_len = second_sep - rcpt_to_pos;
  auto const mf_loc_len  = last_sep - mf_loc_pos;

  auto const reply_hash    = addr.substr(0, first_sep);
  auto const rcpt_to_loc   = addr.substr(rcpt_to_pos, rcpt_to_len);
  auto const mail_from_loc = addr.substr(mf_loc_pos, mf_loc_len);
  auto const mail_from_dom = addr.substr(mf_dom_pos, std::string_view::npos);

  Reply::from_to rep;
  rep.rcpt_to_local_part = rcpt_to_loc;
  rep.mail_from          = fmt::format("{}@{}", mail_from_loc, mail_from_dom);

  auto const hash_enc = hash_rep(rep, secret);

  if (!iequal(reply_hash, hash_enc)) {
    return {};
  }

  return rep;
}

std::optional<Reply::from_to> Reply::dec_reply(std::string_view addr,
                                               std::string_view secret)
{
  // Check for legacy format, process appropriately.
  if (istarts_with(addr, REP_PREFIX)) {
    return old_dec_reply(addr, secret);
  }

  auto const addr_mbx = Mailbox::parse(fmt::format("{}@x.y", addr));
  if (!addr_mbx) {
    throw std::invalid_argument("invalid address syntax in dec_reply");
  }

  // The blob for the address <"x"@y.z> is 26 bytes long.
  if (is_pure_base32(addr)) {
    // if everything is base32 we might have a blob
    if (addr.length() > 25) {
      return dec_reply_blob(addr, secret);
    }
    return {}; // normal local-part
  }

  for (auto sep_char : sep_chars) {
    auto const rep = try_decode(addr, secret, sep_char);
    if (rep)
      return rep;
  }

  LOG(WARNING) << "not a reply address: " << addr;

  return {};
}

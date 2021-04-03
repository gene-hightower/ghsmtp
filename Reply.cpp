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

constexpr int hash_bytes_reply = 6;

constexpr std::string_view REP_PREFIX = "rep=";

constexpr char sep_char = '='; // must match above *_PREFIX values

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
  return h.final().substr(0, hash_bytes_reply);
}

std::string enc_reply_blob(Reply::from_to const& rep, std::string_view secret)
{
  auto const hash = hash_rep(rep, secret);

  auto const pkt = fmt::format("{}{}{}{}{}", // clang-format off
                               hash, '\0',
                               rep.rcpt_to_local_part, '\0',
                               rep.mail_from); // clang-format on

  return fmt::format("{}{}", REP_PREFIX,
                     cppcodec::base32_crockford::encode(pkt));
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

  // If rcpt_to_local_part contain a '=' fall back.
  if (rep.rcpt_to_local_part.find(sep_char) != std::string_view::npos) {
    return enc_reply_blob(rep, secret);
  }

  auto const mail_from = Mailbox(rep.mail_from);

  auto const hash_enc = hash_rep(rep, secret);

  return fmt::format("{}{}{}{}{}{}{}{}", // clang-format off
                     REP_PREFIX,         // includes sep_char
                     hash_enc, sep_char,
                     rep.rcpt_to_local_part, sep_char,
                     mail_from.local_part(), sep_char,
                     mail_from.domain().utf8());
  // clang-format on
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
  auto constexpr alpha =
      std::string_view(cppcodec::detail::base32_crockford_alphabet,
                       sizeof(cppcodec::detail::base32_crockford_alphabet));
  // If we can't find anything not in the base32 alphabet, it's pure
  return s.find_first_not_of(alpha) == std::string_view::npos;
}

std::optional<Reply::from_to> Reply::dec_reply(std::string_view addr,
                                               std::string_view secret)
{
  if (!istarts_with(addr, REP_PREFIX)) {
    LOG(WARNING) << addr << " not a valid reply address";
    return {};
  }
  addr.remove_prefix(REP_PREFIX.length());

  if (is_pure_base32(addr)) {
    // if everything after REP= is base32 we have a blob
    return dec_reply_blob(addr, secret);
  }

  // REP= has been removed, addr is now:
  // {hash}={rcpt_to_local_part}={mail_from.local}={mail_from.domain}
  //       ^1st                 ^2nd              ^last
  // and mail_from.local can contain '=' chars

  auto const first_sep  = addr.find_first_of(sep_char);
  auto const last_sep   = addr.find_last_of(sep_char);
  auto const second_sep = addr.find_first_of(sep_char, first_sep + 1);

  if (first_sep == last_sep || second_sep == last_sep) {
    LOG(WARNING) << "unrecognized reply format " << addr;
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
    LOG(WARNING) << "hash mismatch in reply " << addr;
    LOG(WARNING) << "   reply_hash == " << reply_hash;
    LOG(WARNING) << "     hash_enc == " << hash_enc;
    LOG(WARNING) << "  rcpt_to_loc == " << rcpt_to_loc;
    LOG(WARNING) << "mail_from_loc == " << mail_from_loc;
    LOG(WARNING) << "mail_from_dom == " << mail_from_dom;
    return {};
  }

  return rep;
}

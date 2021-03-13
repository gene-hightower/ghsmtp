#include "SRS0.hpp"

#include "Mailbox.hpp"
#include "iequal.hpp"
#include "is_ascii.hpp"

#include <iterator>

#include "picosha2.h"

#include "SRS.ipp"

#include <cppcodec/base32_crockford.hpp>

#include <arpa/inet.h>
#include <time.h>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

using std::begin;
using std::end;

constexpr int hash_bytes_bounce = 4;
constexpr int hash_bytes_reply  = 6;

constexpr std::string_view SRS_PREFIX = "SRS0=";
constexpr std::string_view REP_PREFIX = "rep=";

constexpr char sep_char = '=';

static std::string hash_rep(SRS0::from_to const& rep)
{
  auto const mail_from = Mailbox(rep.mail_from);
  auto const hb =
      fmt::format("{}{}{}{}", srs_secret, rep.rcpt_to_local_part,
                  mail_from.local_part(), mail_from.domain().ascii());
  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));
  return std::string(reinterpret_cast<char const*>(hash), hash_bytes_reply);
}

std::string enc_reply_blob(SRS0::from_to const& rep)
{
  auto const hash = hash_rep(rep);
  auto const pkt  = fmt::format("{}{}{}{}", hash, rep.rcpt_to_local_part, '\0',
                               rep.mail_from);
  auto const b32  = cppcodec::base32_crockford::encode(pkt);
  return fmt::format("{}{}", REP_PREFIX, b32);
}

std::string SRS0::enc_reply(SRS0::from_to const& rep) const
{
  auto const result = Mailbox::parse(rep.mail_from);
  if (!result) {
    throw std::invalid_argument("invalid mailbox syntax in enc_reply");
  }

  // If it's UTF-8 we must fall back to the blob style.
  if (!is_ascii(result->local)) {
    return enc_reply_blob(rep);
  }

  // If it's "local part"@example.com or local-part@[127.0.0.1] we
  // must fall back to the blob style.
  if (result->local_type == Mailbox::local_types::quoted_string ||
      result->domain_type == Mailbox::domain_types::address_literal) {
    return enc_reply_blob(rep);
  }

  // If rcpt_to_local_part contain a '=' fall back.
  if (rep.rcpt_to_local_part.find(sep_char) != std::string_view::npos) {
    return enc_reply_blob(rep);
  }

  auto const mail_from = Mailbox(rep.mail_from);

  auto const hash_enc = cppcodec::base32_crockford::encode(hash_rep(rep));

  return fmt::format("{}{}{}{}{}{}{}{}", REP_PREFIX, hash_enc, sep_char,
                     rep.rcpt_to_local_part, sep_char, mail_from.local_part(),
                     sep_char, mail_from.domain().ascii());
}

static std::optional<SRS0::from_to> dec_reply_blob(std::string_view addr)
{
  auto const pktv = cppcodec::base32_crockford::decode(addr);
  auto       pkt =
      std::string(reinterpret_cast<char const*>(pktv.data()), pktv.size());

  auto const hash = pkt.substr(0, hash_bytes_reply);
  pkt.erase(0, hash_bytes_reply);

  SRS0::from_to rep;
  rep.rcpt_to_local_part = pkt.c_str();
  pkt.erase(0, rep.rcpt_to_local_part.length() + 1);
  rep.mail_from = pkt;

  auto const hash_computed = hash_rep(rep);

  if (hash_computed != hash) {
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

std::optional<SRS0::from_to> SRS0::dec_reply(std::string_view addr) const
{
  if (!istarts_with(addr, REP_PREFIX)) {
    LOG(WARNING) << addr << " not a valid reply address";
    return {};
  }
  addr.remove_prefix(REP_PREFIX.length());

  if (is_pure_base32(addr)) {
    // if everything after REP= is base32 we have a blob
    return dec_reply_blob(addr);
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

  auto const reply_hash = addr.substr(0, first_sep);

  auto const rcpt_to_pos = first_sep + 1;
  auto const mf_loc_pos  = second_sep + 1;
  auto const mf_dom_pos  = last_sep + 1;

  auto const rcpt_to_len = second_sep - rcpt_to_pos;
  auto const mf_loc_len  = last_sep - mf_loc_pos;

  auto const rcpt_to_loc   = addr.substr(rcpt_to_pos, rcpt_to_len);
  auto const mail_from_loc = addr.substr(mf_loc_pos, mf_loc_len);
  auto const mail_from_dom = addr.substr(mf_dom_pos, std::string_view::npos);

  SRS0::from_to rep;
  rep.rcpt_to_local_part = rcpt_to_loc;
  rep.mail_from          = fmt::format("{}@{}", mail_from_loc, mail_from_dom);

  auto const hash_enc = cppcodec::base32_crockford::encode(hash_rep(rep));

  if (reply_hash != hash_enc) {
    LOG(WARNING) << "hash mismatch in reply " << addr;
    return {};
  }

  return rep;
}

static auto posix_day() { return time(nullptr) / (60 * 60 * 24); }

static std::string enc_posix_day()
{
  auto const d = htons(static_cast<uint16_t>(posix_day()));
  return std::string(reinterpret_cast<char const*>(&d), sizeof(d));
}

static uint16_t dec_posix_day(std::string_view posix_day)
{
  return (static_cast<uint8_t>(posix_day[0]) * 0x100) +
         static_cast<uint8_t>(posix_day[1]);
}

static std::string hash_bounce(SRS0::from_to const& bounce,
                               std::string_view     tstamp)
{
  auto const hb = fmt::format("{}{}{}{}", srs_secret, tstamp, bounce.mail_from,
                              bounce.rcpt_to_local_part);

  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));

  return std::string(reinterpret_cast<char const*>(hash), hash_bytes_bounce);
}

static std::string enc_bounce_blob(SRS0::from_to const& bounce,
                                   char const*          sender)
{
  auto const tstamp = enc_posix_day();
  auto const hash   = hash_bounce(bounce, tstamp);
  auto const pkt    = fmt::format("{}{}{}{}{}", hash, tstamp, bounce.mail_from,
                               '\0', bounce.rcpt_to_local_part);
  auto const b32    = cppcodec::base32_crockford::encode(pkt);
  return fmt::format("{}{}@{}", SRS_PREFIX, b32, sender);
}

std::string SRS0::enc_bounce(SRS0::from_to const& bounce,
                             char const*          sender) const
{
  auto const result = Mailbox::parse(bounce.mail_from);
  if (!result) {
    throw std::invalid_argument("invalid mailbox syntax in enc_bounce");
  }

  // If it's "local part"@example.com or local-part@[127.0.0.1] we
  // must fall back to the blob style.
  if ((result->local_type == Mailbox::local_types::quoted_string) ||
      (result->domain_type == Mailbox::domain_types::address_literal)) {
    return enc_bounce_blob(bounce, sender);
  }

  /*
  auto const for_srs = fmt::format("{}{}{}", bounce.rcpt_to_local_part,
                                   sep_char, bounce.mail_from);
  */
  auto const for_srs = fmt::format("{}", bounce.mail_from);

  return srs_.forward(for_srs.c_str(), sender);
}

static std::optional<SRS0::from_to> dec_bounce_blob(std::string_view addr,
                                                    uint16_t         days_valid)
{
  auto const pktv = cppcodec::base32_crockford::decode(addr);
  auto       pkt =
      std::string(reinterpret_cast<char const*>(pktv.data()), pktv.size());

  auto const hash = pkt.substr(0, hash_bytes_bounce);
  pkt.erase(0, hash_bytes_bounce);
  auto const tstamp = pkt.substr(0, sizeof(uint16_t));
  pkt.erase(0, sizeof(uint16_t));

  SRS0::from_to bounce;
  bounce.mail_from = pkt.c_str();
  pkt.erase(0, bounce.mail_from.length() + 1);
  bounce.rcpt_to_local_part = pkt;

  auto const hash_computed = hash_bounce(bounce, tstamp);

  if (hash_computed != hash) {
    LOG(WARNING) << "hash check failed";
    return {};
  }

  // FIXME in 120 years or so when these numbers wrap
  auto const day = dec_posix_day(tstamp);
  if ((posix_day() - day) > 10) {
    LOG(WARNING) << "bounce address has expired";
    return {};
  }

  return bounce;
}

std::optional<SRS0::from_to> SRS0::dec_bounce(std::string_view addr,
                                              uint16_t         days_valid) const
{
  if (!istarts_with(addr, SRS_PREFIX)) {
    LOG(WARNING) << addr << " not a valid SRS0 address";
    return {};
  }

  auto const minus_prefix =
      addr.substr(SRS_PREFIX.length(), std::string_view::npos);

  auto const at_sign = minus_prefix.find_last_of('@');
  if (at_sign == std::string_view::npos) {
    LOG(WARNING) << addr << " not a valid SRS0 address";
    return {};
  }

  auto const local_part = minus_prefix.substr(0, at_sign);

  if (is_pure_base32(local_part)) {
    return dec_bounce_blob(local_part, days_valid);
  }

  auto const addr_str = std::string(addr.data(), addr.length());

  auto const rev_str = srs_.reverse(addr_str.c_str());

  SRS0::from_to dec;
  dec.mail_from = rev_str;

  return dec;
}

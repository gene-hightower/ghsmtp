#include "SRS0.hpp"

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
constexpr std::string_view REP_PREFIX = "REP=";

static std::string hash_rep(SRS0::from_to const& rep)
{
  auto const hb =
      fmt::format("{}{}{}", srs_secret, rep.mail_from, rep.rcpt_to_local_part);

  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));

  return std::string(reinterpret_cast<char const*>(hash), hash_bytes_reply);
}

std::string SRS0::enc_reply(SRS0::from_to const& rep) const
{
  auto const hash = hash_rep(rep);

  auto const pkt = fmt::format("{}{}{}{}", hash, rep.mail_from, '\0',
                               rep.rcpt_to_local_part);

  auto const b32 = cppcodec::base32_crockford::encode(pkt);
  return fmt::format("{}{}", REP_PREFIX, b32);
}

static bool starts_with(std::string_view str, std::string_view prefix)
{
  return (str.size() >= prefix.size()) &&
         (str.compare(0, prefix.size(), prefix) == 0);
}

std::optional<SRS0::from_to> SRS0::dec_reply(std::string_view addr) const
{
  if (!starts_with(addr, REP_PREFIX)) {
    LOG(WARNING) << addr << " not a valid reply address";
    return {};
  }
  addr.remove_prefix(REP_PREFIX.length());

  auto const pktv = cppcodec::base32_crockford::decode(addr);
  auto       pkt =
      std::string(reinterpret_cast<char const*>(pktv.data()), pktv.size());

  auto const hash = pkt.substr(0, hash_bytes_reply);
  pkt.erase(0, hash_bytes_reply);

  from_to rep;
  rep.mail_from = pkt.c_str();
  pkt.erase(0, rep.mail_from.length() + 1);
  rep.rcpt_to_local_part = pkt;

  auto const hash_computed = hash_rep(rep);

  if (hash_computed != hash) {
    LOG(WARNING) << "hash check failed";
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
                               std::string_view     timestamp)
{
  auto const hb = fmt::format("{}{}{}{}", srs_secret, timestamp,
                              bounce.mail_from, bounce.rcpt_to_local_part);

  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));

  return std::string(reinterpret_cast<char const*>(hash), hash_bytes_bounce);
}

std::string SRS0::enc_bounce(SRS0::from_to const& bounce) const
{
  auto const timestamp = enc_posix_day();

  auto const hash = hash_bounce(bounce, timestamp);

  auto const pkt = fmt::format("{}{}{}{}{}", hash, timestamp, bounce.mail_from,
                               '\0', bounce.rcpt_to_local_part);

  auto const b32 = cppcodec::base32_crockford::encode(pkt);

  return fmt::format("{}{}", SRS_PREFIX, b32);
}

std::optional<SRS0::from_to> SRS0::dec_bounce(std::string_view addr,
                                              uint16_t         days_valid) const
{
  if (!starts_with(addr, SRS_PREFIX)) {
    LOG(WARNING) << addr << " not a valid SRS0 address";
    return {};
  }
  addr.remove_prefix(SRS_PREFIX.length());

  auto const pktv = cppcodec::base32_crockford::decode(addr);
  auto       pkt =
      std::string(reinterpret_cast<char const*>(pktv.data()), pktv.size());

  auto const hash = pkt.substr(0, hash_bytes_bounce);
  pkt.erase(0, hash_bytes_bounce);

  auto const timestamp = pkt.substr(0, sizeof(uint16_t));
  pkt.erase(0, sizeof(uint16_t));

  from_to bounce;
  bounce.mail_from = pkt.c_str();
  pkt.erase(0, bounce.mail_from.length() + 1);
  bounce.rcpt_to_local_part = pkt;

  auto const hash_computed = hash_bounce(bounce, timestamp);

  if (hash_computed != hash) {
    LOG(WARNING) << "hash check failed";
    return {};
  }

  // FIXME in 120 years or so when these numbers wrap
  auto const day = dec_posix_day(timestamp);
  if ((posix_day() - day) > 10) {
    LOG(WARNING) << "bounce address has expired";
    return {};
  }

  return bounce;
}

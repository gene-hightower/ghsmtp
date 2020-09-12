#include "SRS0.hpp"

#include <iterator>

#include "picosha2.h"

#include "SRS.ipp"

#include <cppcodec/base32_crockford.hpp>

#include <snappy.h>

#include <time.h>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

using std::begin;
using std::end;

constexpr int hash_bytes_bounce = 4;
constexpr int hash_bytes_reply  = 6;

constexpr std::string_view SRS_PREFIX = "SRS0=";

template <typename Input>
static std::string_view make_view(Input const& in)
{
  return std::string_view(reinterpret_cast<char const*>(begin(in)),
                          std::distance(begin(in), end(in)));
}

std::string SRS0::enc_reply(SRS0::reply_address const& rep) const
{
  auto const hb =
      fmt::format("{}{}{}", srs_secret, rep.mail_from, rep.rcpt_to_local_part);

  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));

  auto hash_view = make_view(hash);
  hash_view.remove_suffix(hash_view.size() - hash_bytes_reply);

  auto const pkt = fmt::format("{}{}{}{}", hash_view, rep.mail_from, '\0',
                               rep.rcpt_to_local_part);

  std::string compressed;
  snappy::Compress(pkt.data(), pkt.size(), &compressed);

  auto const b32 = cppcodec::base32_crockford::encode(compressed);
  return fmt::format("{}{}", SRS_PREFIX, b32);
}

static bool starts_with(std::string_view str, std::string_view prefix)
{
  return (str.size() >= prefix.size()) &&
         (str.compare(0, prefix.size(), prefix) == 0);
}

std::optional<SRS0::reply_address> SRS0::dec_reply(std::string_view addr) const
{
  if (!starts_with(addr, SRS_PREFIX)) {
    LOG(WARNING) << addr << " not a valid SRS0 address";
    return {};
  }
  addr.remove_prefix(SRS_PREFIX.length());

  auto const compressed = cppcodec::base32_crockford::decode(addr);

  std::string pkt;
  snappy::Uncompress(reinterpret_cast<char const*>(compressed.data()),
                     compressed.size(), &pkt);

  auto const hash_pfx = pkt.substr(0, hash_bytes_reply);
  pkt.erase(0, hash_bytes_reply);

  reply_address rep;
  rep.mail_from = pkt.c_str();
  pkt.erase(0, rep.mail_from.length() + 1);
  rep.rcpt_to_local_part = pkt;

  auto const hb =
      fmt::format("{}{}{}", srs_secret, rep.mail_from, rep.rcpt_to_local_part);

  unsigned char hash[picosha2::k_digest_size];
  picosha2::hash256(begin(hb), end(hb), begin(hash), end(hash));

  auto const hash_view = make_view(hash);

  if (!starts_with(hash_view, hash_pfx)) {
    LOG(WARNING) << "hash check failed";
    return {};
  }

  return rep;
}

std::string SRS0::enc_bounce(SRS0::bounce_address const& bounce_info) const
{
  // stuff
  return "";
}

std::optional<SRS0::bounce_address>
SRS0::dec_bounce(std::string_view addr) const
{
  return {};
}

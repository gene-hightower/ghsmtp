#include "DNS.hpp"

#include "DNS-iostream.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "Sock.hpp"

#include <atomic>
#include <limits>
#include <memory>
#include <tuple>

#include <arpa/nameser.h>

#include <experimental/random>

#include <glog/logging.h>

#include "osutil.hpp"

DEFINE_bool(log_dns_data, false, "log all DNS TCP protocol data");

namespace Config {
// The default timeout in glibc is 5 seconds.  My setup with unbound
// in front of stubby with DNSSEC checking and all that seems to work
// better with just a little more time.

auto constexpr read_timeout{std::chrono::seconds(7)};

enum class sock_type : bool { stream, dgram };

struct nameserver {
  char const* host; // name used to match cert
  char const* addr;
  char const* port;
  sock_type   typ;
};

constexpr nameserver nameservers[]{
    {
        "one.one.one.one",
        "1.1.1.1",
        "domain-s",
        sock_type::stream,
    },
    {
        "localhost",
        "127.0.0.1",
        "domain",
        sock_type::stream,
    },
    {
        "localhost",
        "::1",
        "domain",
        sock_type::stream,
    },
    /*
    {
        "one.one.one.one",
        "1.1.1.1",
        "domain",
        sock_type::dgram,
    },
    {
        "dns.google",
        "8.8.8.8",
        "domain",
        sock_type::dgram,
    },
    {
        "dns.google",
        "8.8.4.4",
        "domain",
        sock_type::dgram,
    },

    {
        "dns.google",
        "2001:4860:4860::8888",
        "domain",
        sock_type::dgram,
    },
    {
        "dns.google",
        "2001:4860:4860::8844",
        "domain",
        sock_type::dgram,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "1.0.0.1",
        "domain-s",
        sock_type::stream,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1111",
        "domain-s",
        sock_type::stream,
    },
    {
        "1dot1dot1dot1.cloudflare-dns.com",
        "2606:4700:4700::1001",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns9.quad9.net",
        "9.9.9.9",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns10.quad9.net",
        "9.9.9.10",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns10.quad9.net",
        "149.112.112.10",
        "domain-s",
        sock_type::stream,
    },
    {
        "dns10.quad9.net",
        "2620:fe::10",
        "domain-s",
        sock_type::stream,
    },
    */
};
} // namespace Config

template <typename T, std::size_t N>
constexpr std::size_t countof(T const (&)[N]) noexcept
{
  return N;
}

namespace DNS {

Resolver::Resolver(fs::path config_path)
{
  auto tries = countof(Config::nameservers);

  ns_ = std::experimental::randint(
      0, static_cast<int>(countof(Config::nameservers) - 1));

  while (tries--) {

    // try the next one, with wrap
    if (++ns_ == countof(Config::nameservers))
      ns_ = 0;

    auto const& nameserver = Config::nameservers[ns_];

    auto typ = (nameserver.typ == Config::sock_type::stream) ? SOCK_STREAM
                                                             : SOCK_DGRAM;
    uint16_t port =
        osutil::get_port(nameserver.port, (typ == SOCK_STREAM) ? "tcp" : "udp");
    ns_fd_ = -1;

    if (IP4::is_address(nameserver.addr)) {
      ns_fd_ = socket(AF_INET, typ, 0);
      PCHECK(ns_fd_ >= 0) << "socket() failed";

      auto in4{sockaddr_in{}};
      in4.sin_family = AF_INET;
      in4.sin_port   = htons(port);
      CHECK_EQ(inet_pton(AF_INET, nameserver.addr,
                         reinterpret_cast<void*>(&in4.sin_addr)),
               1);
      if (connect(ns_fd_, reinterpret_cast<const sockaddr*>(&in4),
                  sizeof(in4))) {
        PLOG(INFO) << "connect failed " << nameserver.host << '['
                   << nameserver.addr << "]:" << nameserver.port;
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
    }
    else if (IP6::is_address(nameserver.addr)) {
      ns_fd_ = socket(AF_INET6, typ, 0);
      PCHECK(ns_fd_ >= 0) << "socket() failed";

      auto in6{sockaddr_in6{}};
      in6.sin6_family = AF_INET6;
      in6.sin6_port   = htons(port);
      CHECK_EQ(inet_pton(AF_INET6, nameserver.addr,
                         reinterpret_cast<void*>(&in6.sin6_addr)),
               1);
      if (connect(ns_fd_, reinterpret_cast<const sockaddr*>(&in6),
                  sizeof(in6))) {
        PLOG(INFO) << "connect failed " << nameserver.host << '['
                   << nameserver.addr << "]:" << nameserver.port;
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
    }

    POSIX::set_nonblocking(ns_fd_);

    if (nameserver.typ == Config::sock_type::stream) {
      ns_sock_ = std::make_unique<Sock>(ns_fd_, ns_fd_);
      if (FLAGS_log_dns_data) {
        ns_sock_->log_data_on();
      }
      else {
        ns_sock_->log_data_off();
      }

      if (port != 53) {
        DNS::RR_collection tlsa_rrs; // empty FIXME!
        ns_sock_->starttls_client(config_path, nullptr, nameserver.host,
                                  tlsa_rrs, false);
        if (ns_sock_->verified()) {
          ns_fd_ = -1;
          return;
        }
        close(ns_fd_);
        ns_fd_ = -1;
        continue;
      }
      ns_fd_ = -1;
    }

    return;
  }

  LOG(FATAL) << "no nameservers left to try";
}

message Resolver::xchg(message const& q)
{
  if (Config::nameservers[ns_].typ == Config::sock_type::stream) {
    CHECK_EQ(ns_fd_, -1);

    uint16_t sz = htons(std::size(q));

    ns_sock_->out().write(reinterpret_cast<char const*>(&sz), sizeof sz);
    ns_sock_->out().write(reinterpret_cast<char const*>(begin(q)), size(q));
    ns_sock_->out().flush();

    sz = 0;
    ns_sock_->in().read(reinterpret_cast<char*>(&sz), sizeof sz);
    sz = ntohs(sz);

    DNS::message::container_t bfr(sz);
    ns_sock_->in().read(reinterpret_cast<char*>(bfr.data()), sz);
    CHECK_EQ(ns_sock_->in().gcount(), std::streamsize(sz));

    if (!ns_sock_->in()) {
      LOG(WARNING) << "Resolver::xchg was able to read only "
                   << ns_sock_->in().gcount() << " octets";
    }

    return message{std::move(bfr)};
  }

  CHECK(Config::nameservers[ns_].typ == Config::sock_type::dgram);
  CHECK_GE(ns_fd_, 0);

  CHECK_EQ(send(ns_fd_, std::begin(q), std::size(q), 0), std::size(q));

  DNS::message::container_t bfr(Config::max_udp_sz);

  auto constexpr hook{[]() {}};
  auto       t_o{false};
  auto const a_buf = reinterpret_cast<char*>(bfr.data());
  auto const a_buflen = POSIX::read(ns_fd_, a_buf, int(Config::max_udp_sz),
                                    hook, Config::read_timeout, t_o);

  if (a_buflen < 0) {
    LOG(WARNING) << "DNS read failed";
    return message{0};
  }

  if (t_o) {
    LOG(WARNING) << "DNS read timed out";
    return message{0};
  }

  bfr.resize(a_buflen);
  bfr.shrink_to_fit();

  return message{std::move(bfr)};
}

RR_collection Resolver::get_records(RR_type typ, char const* name)
{
  Query q(*this, typ, name);
  return q.get_records();
}

std::vector<std::string> Resolver::get_strings(RR_type typ, char const* name)
{
  Query q(*this, typ, name);
  return q.get_strings();
}

bool Query::xchg_(Resolver& res, uint16_t id)
{
  auto tries = 3;

  while (tries) {

    a_ = res.xchg(q_);

    if (!size(a_)) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "no reply from nameserver";
      return false;
    }

    if (size(a_) < min_message_sz()) {
      bogus_or_indeterminate_ = true;
      LOG(WARNING) << "packet too small";
      return false;
    }

    if (a_.id() == id)
      break;

    LOG(WARNING) << "packet out of order; ids don't match, got " << a_.id()
                 << " expecting " << id;
    --tries;
  }

  if (tries)
    return true;

  bogus_or_indeterminate_ = true;
  LOG(WARNING) << "no tries left, giving up";

  return false;
}

Query::Query(Resolver& res, RR_type type, char const* name)
  : type_(type)
{
  static_assert(std::numeric_limits<uint16_t>::min() == 0);
  static_assert(std::numeric_limits<uint16_t>::max() == 65535);

  uint16_t id =
      std::experimental::randint(std::numeric_limits<uint16_t>::min(),
                                 std::numeric_limits<uint16_t>::max());

  uint16_t cls = ns_c_in;

  q_ = create_question(name, type, cls, id);

  if (!xchg_(res, id))
    return;

  if (size(a_) < min_message_sz()) {
    bogus_or_indeterminate_ = true;
    LOG(INFO) << "bad (or no) reply for " << name << '/' << type;
    return;
  }

  check_answer(nx_domain_, bogus_or_indeterminate_, rcode_, extended_rcode_,
               truncation_, authentic_data_, has_record_, q_, a_, type, name);

  if (truncation_) {
    // if UDP, retry with TCP
    bogus_or_indeterminate_ = true;
    LOG(INFO) << "truncated answer for " << name << '/' << type;
  }
}

RR_collection Query::get_records()
{
  if (bogus_or_indeterminate_)
    return RR_collection{};

  return DNS::get_records(a_, bogus_or_indeterminate_);
}

std::vector<std::string> Query::get_strings()
{
  std::vector<std::string> ret;

  auto const rr_set = get_records();

  for (auto rr : rr_set) {
    std::visit(
        [&ret, type = type_](auto const& r) {
          if (type == r.rr_type()) {
            auto const s = r.as_str();
            if (s)
              ret.push_back(*s);
          }
        },
        rr);
  }

  return ret;
}

} // namespace DNS

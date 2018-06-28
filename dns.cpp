#include "DNS.hpp"
#include "DNS-fcrdns.hpp"
#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"

#include <iostream>

#include <experimental/iterator>

#include <fmt/format.h>

using namespace std::string_literals;

void check_dnsrbl(DNS::Resolver& res, char const* a)
{
  char const* rbls[]{
      "b.barracudacentral.org",
      "psbl.surriel.com",
      "zen.spamhaus.org",
  };

  auto const reversed{IP4::reverse(a)};

  for (auto rbl : rbls) {
    if (has_record(res, DNS::RR_type::A, reversed + rbl)) {
      std::cout << a << " blocked on advice from " << rbl << '\n';
    }
  }
}

void do_addr(DNS::Resolver& res, char const* a)
{
  auto const names = DNS::fcrdns(res, a);
  for (auto name : names) {
    std::cout << name << '\n';
  }
  if (names.empty()) {
    if (IP4::is_address(a)) {
      auto const reversed{IP4::reverse(a)};
      auto const ptrs
          = res.get_strings(DNS::RR_type::PTR, reversed + "in-addr.arpa");
      for (auto ptr : ptrs) {
        std::cout << "is a PTR to " << ptr << '\n';
      }
      check_dnsrbl(res, a);
    }
    if (IP6::is_address(a)) {
      auto const reversed{IP6::reverse(a)};
      auto const ptrs
          = res.get_strings(DNS::RR_type::PTR, reversed + "ip6.arpa");
      for (auto ptr : ptrs) {
        std::cout << "is a PTR to " << ptr << '\n';
      }
    }
  }
}

void do_domain(DNS::Resolver& res, char const* dom_cp)
{
  auto const dom{Domain{dom_cp}};

  auto const as = res.get_strings(DNS::RR_type::A, dom.ascii().c_str());
  for (auto a : as) {
    std::cout << a;
    auto const names = DNS::fcrdns(res, a);
    std::vector<Domain> doms;
    for (auto const& name : names) {
      doms.emplace_back(name);
    }
    if (!doms.empty()) {
      std::cout << " [";
      std::copy(doms.begin(), doms.end(),
                std::experimental::make_ostream_joiner(std::cout, ", "));
      std::cout << ']';
    }

    std::cout << '\n';
  }

  auto aaaas = res.get_strings(DNS::RR_type::AAAA, dom.ascii().c_str());
  for (auto aaaa : aaaas) {
    std::cout << aaaa << '\n';
  }

  char const* uribls[]{
      "black.uribl.com",
      "dbl.spamhaus.org",
      "multi.surbl.org",
  };

  for (auto uribl : uribls) {
    auto const lookup = fmt::format("{}.{}", dom.ascii(), uribl);
    if (DNS::has_record(res, DNS::RR_type::A, lookup)) {
      std::cout << dom << " blocked on advice from " << uribl << '\n';
    }
  }
}

int main(int argc, char* argv[])
{
  DNS::Resolver res;

  for (int i = 1; i < argc; ++i) {
    auto const arg = argv[i];
    if (IP::is_address(arg)) {
      do_addr(res, arg);
    }
    else {
      do_domain(res, arg);
    }
  }
}

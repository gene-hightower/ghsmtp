#include "DNS.hpp"
#include "DNS-fcrdns.hpp"
#include "IP.hpp"
#include "IP4.hpp"
#include "IP6.hpp"
#include "TLD.hpp"

#include <iomanip>
#include <iostream>

#include <experimental/iterator>

#include <fmt/format.h>

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
      std::cout << a << " blocked on advice from " << rbl;
      std::cout << '\n';
    }
  }
}

void do_addr(DNS::Resolver& res, char const* a)
{
  std::cout << a;

  auto const names = DNS::fcrdns(res, a);
  std::vector<Domain> doms;
  for (auto const& name : names) {
    doms.emplace_back(name);
  }
  if (!doms.empty()) {
    std::cout << " [";
    std::copy(begin(doms), end(doms),
              std::experimental::make_ostream_joiner(std::cout, ", "));
    std::cout << ']';
    std::cout << '\n';
  }

  if (names.empty()) {
    if (IP4::is_address(a)) {
      auto const reversed{IP4::reverse(a)};
      auto const ptrs
          = res.get_strings(DNS::RR_type::PTR, reversed + "in-addr.arpa");
      for (auto const& ptr : ptrs) {
        std::cout << " has a PTR to " << ptr;
        std::cout << '\n';
      }
      check_dnsrbl(res, a);
    }
    if (IP6::is_address(a)) {
      auto const reversed{IP6::reverse(a)};
      auto const ptrs
          = res.get_strings(DNS::RR_type::PTR, reversed + "ip6.arpa");
      for (auto const& ptr : ptrs) {
        std::cout << " has a PTR to " << ptr;
        std::cout << '\n';
      }
    }
  }

}

void do_domain(DNS::Resolver& res, char const* dom_cp)
{
  auto const dom{Domain{dom_cp}};

  auto cnames = res.get_strings(DNS::RR_type::CNAME, dom.ascii().c_str());
  if (!cnames.empty()) {
    std::cout << "is an alias for ";
    std::copy(begin(cnames), end(cnames),
              std::experimental::make_ostream_joiner(std::cout, ", "));
    std::cout << '\n';
  }

  auto as = res.get_strings(DNS::RR_type::A, dom.ascii().c_str());
  for (auto const& a : as) {
    do_addr(res, a.c_str());
  }

  auto aaaas = res.get_strings(DNS::RR_type::AAAA, dom.ascii().c_str());
  for (auto const& aaaa : aaaas) {
    do_addr(res, aaaa.c_str());
  }

  TLD tld_db;
  auto reg_dom{tld_db.get_registered_domain(dom.ascii())};
  if (dom != reg_dom) {
    std::cout << "registerd domain " << reg_dom << '\n';
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

  auto q{DNS::Query{res, DNS::RR_type::MX, dom.ascii()}};
  if (q.authentic_data()) {
    std::cout << "MX records authentic for domain " << dom << '\n';
  }

  auto mxs{q.get_records()};

  mxs.erase(std::remove_if(begin(mxs), end(mxs),
                           [](auto const& rr) {
                             return !std::holds_alternative<DNS::RR_MX>(rr);
                           }),
            end(mxs));

  if (!mxs.empty())
    std::cout << "mail for " << dom << " is handled by\n";

  std::sort(begin(mxs), end(mxs), [](auto const& a, auto const& b) {
    if (std::holds_alternative<DNS::RR_MX>(a)
        && std::holds_alternative<DNS::RR_MX>(b)) {
      if (std::get<DNS::RR_MX>(a).preference()
          == std::get<DNS::RR_MX>(b).preference())
        return std::get<DNS::RR_MX>(a).exchange()
               < std::get<DNS::RR_MX>(b).exchange();
      return std::get<DNS::RR_MX>(a).preference()
             < std::get<DNS::RR_MX>(b).preference();
    }
    return false;
  });

  for (auto const& mx : mxs) {
    if (std::holds_alternative<DNS::RR_MX>(mx)) {
      auto x = std::get<DNS::RR_MX>(mx);
      std::cout << std::setfill(' ') << std::setw(3) << x.preference() << ' '
                << x.exchange() << '\n';
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

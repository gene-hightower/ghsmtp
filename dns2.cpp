/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright (C) 2013  Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// brain dead command line tool to query DNS

#include "DNS.hpp"
#include "IP4.hpp"

void do_dotted_quad(char const* addr)
{
  DNS::Resolver res;

  std::string reversed{IP4::reverse(addr)};

  constexpr const char* const rbls[]
      = {"zen.spamhaus.org", "b.barracudacentral.org"};

  for (auto rbl : rbls) {
    std::string lookup = reversed + rbl;

    DNS::Domain dom(lookup.c_str());
    DNS::Query<DNS::RR_type::A> q(res, dom);

    if (q.get_rcode() == DNS::Pkt_rcode::NOERROR) {
      DNS::Rrlist<DNS::RR_type::A> rrlst(q);

      if (!rrlst.empty()) {
        std::cout << "found in " << rbl << std::endl;
        std::vector<std::string> codes = rrlst.get();
        for (auto code : codes) {
          std::cout << code << std::endl;
        }
      }
    }
    else {
      if (q.get_rcode() == DNS::Pkt_rcode::NXDOMAIN) {
        std::cout << "not found in " << rbl << std::endl;
      }
      else {
        std::cout << "Error from lookup at " << rbl << " " << q.get_rcode()
                  << std::endl;
      }
    }
  }

  std::string fcrdns;

  std::vector<std::string> ptrs
      = DNS::get_records<DNS::RR_type::PTR>(res, reversed + "in-addr.arpa");

  for (auto ptr : ptrs) {
    // chop off the trailing '.'
    int last = ptr.length() - 1;
    if ((-1 != last) && ('.' == ptr.at(last))) {
      ptr.erase(last, 1);
    }
    std::vector<std::string> addrs
        = DNS::get_records<DNS::RR_type::A>(res, ptr);
    for (const auto a : addrs) {
      if (a == addr) {
        fcrdns = ptr;
        goto found;
      }
    }
  }

  std::cout << "no fcrdns" << std::endl;
  return;

found:
  std::cout << fcrdns << std::endl;

  std::vector<std::string> txts
      = DNS::get_records<DNS::RR_type::TXT>(res, fcrdns);
  for (const auto txt : txts) {
    std::cout << "\"" << txt << "\"" << std::endl;
  }
}

void do_domain(char const* domain)
{
  DNS::Resolver res;

  std::vector<std::string> addrs
      = DNS::get_records<DNS::RR_type::A>(res, domain);
  for (const auto a : addrs) {
    std::cout << a << std::endl;
  }

  std::vector<std::string> txts
      = DNS::get_records<DNS::RR_type::TXT>(res, domain);
  for (const auto txt : txts) {
    std::cout << "\"" << txt << "\"" << std::endl;
  }
}

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  for (int i = 1; i < argc; ++i) {
    if (IP4::is_address(argv[i])) {
      do_dotted_quad(argv[i]);
    }
    else {
      do_domain(argv[i]);
    }
  }
}

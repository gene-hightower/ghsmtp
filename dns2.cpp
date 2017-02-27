/*
    This file is part of ghsmtp - Gene's simple SMTP server.
    Copyright © 2013-2017 Gene Hightower <gene@digilicious.com>

    This program is free software: you can redistribute it and/or
    modify it under the terms of the GNU Affero General Public License
    as published by the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with this program.  See the file COPYING.  If not,
    see <http://www.gnu.org/licenses/>.

    Additional permission under GNU AGPL version 3 section 7

    If you modify this program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a
    modified version of that library), containing parts covered by the
    terms of the OpenSSL or SSLeay licenses, I, Gene Hightower grant
    you additional permission to convey the resulting work.
    Corresponding Source for a non-source form of such a combination
    shall include the source code for the parts of OpenSSL used as
    well as that of the covered work.
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
        std::cout << "found in " << rbl << '\n';
        std::vector<std::string> codes = rrlst.get();
        for (auto code : codes) {
          std::cout << code << '\n';
        }
      }
    }
    else {
      if (q.get_rcode() == DNS::Pkt_rcode::NXDOMAIN) {
        std::cout << "not found in " << rbl << '\n';
      }
      else {
        std::cout << "Error from lookup at " << rbl << " " << q.get_rcode()
                  << '\n';
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

  std::cout << "no fcrdns\n";
  return;

found:
  std::cout << fcrdns << '\n';

  std::vector<std::string> txts
      = DNS::get_records<DNS::RR_type::TXT>(res, fcrdns);
  for (const auto txt : txts) {
    std::cout << "\"" << txt << "\"\n";
  }
}

void do_domain(char const* domain)
{
  DNS::Resolver res;

  std::vector<std::string> addrs
      = DNS::get_records<DNS::RR_type::A>(res, domain);
  for (const auto a : addrs) {
    std::cout << a << '\n';
  }

  std::vector<std::string> txts
      = DNS::get_records<DNS::RR_type::TXT>(res, domain);
  for (const auto txt : txts) {
    std::cout << "\"" << txt << "\"\n";
  }
}

int main(int argc, char const* argv[])
{
  google::InitGoogleLogging(argv[0]);

  for (int i = 1; i < argc; ++i) {
    if (IP4::is_address(argv[i])) {
      do_dotted_quad(argv[i]);
    }
    else {
      do_domain(argv[i]);
    }
  }
}

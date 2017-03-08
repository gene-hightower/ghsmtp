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

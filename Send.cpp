#include "Send.hpp"

namespace {
std::vector<Domain>
get_exchangers(DNS::Resolver& res, Domain const& domain, bool& enforce_dane)
{
  auto exchangers{std::vector<Domain>{}};

  // User provided explicit host to receive mail.
  if (!FLAGS_mx_host.empty()) {
    exchangers.emplace_back(FLAGS_mx_host);
    return exchangers;
  }

  // Non-local part is an address literal.
  if (domain.is_address_literal()) {
    exchangers.emplace_back(domain);
    return exchangers;
  }

  // RFC 5321 section 5.1 "Locating the Target Host"

  // “The lookup first attempts to locate an MX record associated with
  //  the name.  If a CNAME record is found, the resulting name is
  //  processed as if it were the initial name.”

  // Our (full) resolver will traverse any CNAMEs for us and return
  // the CNAME and MX records all together.

  auto const& dom = domain.ascii();

  auto q_sts{DNS::Query{res, DNS::RR_type::TXT, "_mta-sts."s + dom}};
  if (q_sts.has_record()) {
    auto sts_records = q_sts.get_strings();
    sts_records.erase(std::remove_if(begin(sts_records), end(sts_records),
                                     std::not_fn(sts_rec)),
                      end(sts_records));
    if (size(sts_records) == 1) {
      LOG(INFO) << "### This domain implements MTA-STS ###";
    }
  }
  else {
    LOG(INFO) << "MTA-STS record not found for domain " << dom;
  }

  auto q{DNS::Query{res, DNS::RR_type::MX, dom}};
  if (q.has_record()) {
    if (q.authentic_data()) {
      LOG(INFO) << "### MX records authentic for domain " << dom << " ###";
    }
    else {
      LOG(INFO) << "MX records can't be authenticated for domain " << dom;
      enforce_dane = false;
    }
  }
  auto mxs{q.get_records()};

  mxs.erase(std::remove_if(begin(mxs), end(mxs), is_localhost), end(mxs));

  auto const nmx = std::count_if(begin(mxs), end(mxs), [](auto const& rr) {
    return std::holds_alternative<DNS::RR_MX>(rr);
  });

  if (nmx == 1) {
    for (auto const& mx : mxs) {
      if (std::holds_alternative<DNS::RR_MX>(mx)) {
        // RFC 7505 null MX record
        if ((std::get<DNS::RR_MX>(mx).preference() == 0)
            && (std::get<DNS::RR_MX>(mx).exchange().empty()
                || (std::get<DNS::RR_MX>(mx).exchange() == "."))) {
          LOG(INFO) << "domain " << dom << " does not accept mail";
          return exchangers;
        }
      }
    }
  }

  if (nmx == 0) {
    // domain must have address record
    exchangers.emplace_back(dom);
    return exchangers;
  }

  // […] then the sender-SMTP MUST randomize them to spread the load
  // across multiple mail exchangers for a specific organization.
  std::shuffle(begin(mxs), end(mxs), std::random_device());
  std::sort(begin(mxs), end(mxs), [](auto const& a, auto const& b) {
    if (std::holds_alternative<DNS::RR_MX>(a)
        && std::holds_alternative<DNS::RR_MX>(b)) {
      return std::get<DNS::RR_MX>(a).preference()
             < std::get<DNS::RR_MX>(b).preference();
    }
    return false;
  });

  if (nmx)
    LOG(INFO) << "MXs for " << domain << " are:";

  for (auto const& mx : mxs) {
    if (std::holds_alternative<DNS::RR_MX>(mx)) {
      exchangers.emplace_back(std::get<DNS::RR_MX>(mx).exchange());
      LOG(INFO) << std::setfill(' ') << std::setw(3)
                << std::get<DNS::RR_MX>(mx).preference() << " "
                << std::get<DNS::RR_MX>(mx).exchange();
    }
  }

  return exchangers;
}
} // namespace

Send::Send(DNS::Resolver& res, Domain domain)
  : domain_(domain)
{
  auto const& dom = domain_.ascii();
  exchangers_ = get_exchangers(res, domain);
}

#ifndef DNS_DOT_HPP
#define DNS_DOT_HPP

#include <memory>

#include "DNS-packet.hpp"
#include "DNS-rrs.hpp"
#include "Sock.hpp"
#include "iobuffer.hpp"

#include <glog/logging.h>

namespace DNS {

class Resolver {
public:
  Resolver(Resolver const&) = delete;
  Resolver& operator=(Resolver const&) = delete;

  Resolver(fs::path config_path);

  RR_collection get_records(RR_type typ, char const* name);
  RR_collection get_records(RR_type typ, std::string const& name)
  {
    return get_records(typ, name.c_str());
  }

  std::vector<std::string> get_strings(RR_type typ, char const* name);
  std::vector<std::string> get_strings(RR_type typ, std::string const& name)
  {
    return get_strings(typ, name.c_str());
  }

  packet xchg(packet const& q);

private:
  std::unique_ptr<Sock> ns_sock_;
  int                   ns_;
  int                   ns_fd_;
};

class Query {
public:
  Query(Query const&) = delete;
  Query& operator=(Query const&) = delete;

  Query(Resolver& res, RR_type type, char const* name);
  Query(Resolver& res, RR_type type, std::string const& name)
    : Query(res, type, name.c_str())
  {
  }

  bool authentic_data() const { return authentic_data_; }
  bool bogus_or_indeterminate() const { return bogus_or_indeterminate_; }
  bool nx_domain() const { return nx_domain_; }

  bool                     has_record() const { return has_record_; }
  RR_collection            get_records();
  std::vector<std::string> get_strings();

  uint16_t rcode() const { return rcode_; }
  uint16_t extended_rcode() const { return extended_rcode_; }

private:
  bool xchg_(Resolver& res, uint16_t id);
  void check_answer_(Resolver& res, RR_type type, char const* name);

  uint16_t rcode_{0};
  uint16_t extended_rcode_{0};

  RR_type type_;

  packet q_;
  packet a_;

  bool authentic_data_{false};
  bool bogus_or_indeterminate_{false};
  bool nx_domain_{false};
  bool has_record_{false};
};

inline std::vector<std::string>
get_strings(Resolver& res, RR_type type, char const* name)
{
  return res.get_strings(type, name);
}

inline std::vector<std::string>
get_strings(Resolver& res, RR_type type, std::string const& name)
{
  return res.get_strings(type, name.c_str());
}

inline bool has_record(Resolver& res, RR_type type, char const* name)
{
  Query q(res, type, name);
  return q.has_record();
}

inline bool has_record(Resolver& res, RR_type type, std::string const& name)
{
  return has_record(res, type, name.c_str());
}
} // namespace DNS

#endif // DNS_DOT_HPP

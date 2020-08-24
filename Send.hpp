#ifndef SEND_DOT_HPP
#define SEND_DOT_HPP

#include "DNS.hpp"
#include "Mailbox.hpp"

class Send {
public:
  Send(DNS::Resolver& res, Domain domain);

  bool mail_from(Mailbox sender);
  bool rcpt_to(Mailbox recipient);

  bool data(char const* data, size_t length);

private:
  Domain domain_;
  Mailbox from_;
  std::vector<Mailbox> to_;

  std::vector<Domain> exchangers_;
};

#endif // SEND_DOT_HPP

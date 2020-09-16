#include "SRS.hpp"

#include "Mailbox.hpp"

#include <gflags/gflags.h>

#include <glog/logging.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

void check_mbx(std::string_view mbx)
{
  if (!Mailbox::validate(mbx))
    LOG(ERROR) << "invalid mailbox: " << mbx;
}

int main(int argc, char* argv[])
{
  std::ios::sync_with_stdio(false);
  google::ParseCommandLineFlags(&argc, &argv, true);

  SRS srs;

  char const* sender = "gene@digilicious.com";
  // libsrs seems to choke on Unicode in the domain
  // char const* alias  = "♥.digilicious.com";
  char const* alias  = "xn--g6h.digilicious.com";
  char const* alias2 = "xn--g6h.example.com";

  LOG(INFO) << "sender == " << sender;
  LOG(INFO) << "alias  == " << alias;

  auto const fwd = srs.forward(sender, alias);
  LOG(INFO) << "  fwd  == " << fwd;

  auto const fwd2 = srs.forward(fwd.c_str(), alias2);
  LOG(INFO) << "  fwd2 == " << fwd2;

  auto const rev = srs.reverse(fwd.c_str());
  LOG(INFO) << "   rev == " << rev;

  check_mbx(sender);
  check_mbx(fwd);
  check_mbx(fwd2);
  check_mbx(rev);

  CHECK_EQ(rev, sender);
}

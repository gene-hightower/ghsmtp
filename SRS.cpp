#include "SRS.hpp"

#include <srs2.h>

#include <glog/logging.h>

#include "SRS.ipp"

SRS::SRS()
  : srs_(srs_new())
{
  add_secret(srs_secret);
}

SRS::~SRS() { srs_free(srs_); }

std::string SRS::forward(char const* sender, char const* alias)
{
  char buf[1024]; // will be of size at most strlen(sender) + strlen(alias) + 64
  CHECK_EQ(srs_forward(srs_, buf, sizeof(buf), sender, alias), SRS_SUCCESS);
  return std::string(buf);
}

std::string SRS::reverse(char const* sender)
{
  char buf[1024]; // no longer than sender
  CHECK_EQ(srs_reverse(srs_, buf, sizeof(buf), sender), SRS_SUCCESS);
  return std::string(buf);
}

void SRS::add_secret(char const* secret) { srs_add_secret(srs_, secret); }

#ifndef HASH_DOT_HPP
#define HASH_DOT_HPP

#include <string>
#include <string_view>

#include <openssl/sha.h>

#include <glog/logging.h>

#include <cppcodec/base32_crockford.hpp>

class Hash {
public:
  Hash() { CHECK_EQ(SHA256_Init(&c), 1); }

  void update(std::string_view s)
  {
    CHECK_EQ(SHA256_Update(&c, s.data(), s.length()), 1);
  }

  std::string final()
  {
    unsigned char md[SHA256_DIGEST_LENGTH];
    CHECK_EQ(SHA256_Final(md, &c), 1);
    return cppcodec::base32_crockford::encode(md);
  }

private:
  SHA256_CTX c;
};

#endif // HASH_DOT_HPP

#include "Hash.hpp"

int main()
{
  Hash h;
  h.update("The quick brown fox jumps over the lazy dog");
  CHECK_EQ(h.final(), "TYMFQCR7TY098TEAKAYB021E9Y6NCMF4DMYDPXHD0B8BYDY9WP90");
}

#include "Base64.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  constexpr char const* text = R"(
“We are all in the gutter, but some of us are looking at the stars.”
                                                     ― Oscar Wilde
)";

  CHECK_EQ(Base64::dec(Base64::enc(text)), text);

  std::string s = text;

  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);

  constexpr char const* empty = "";
  CHECK_EQ(Base64::dec(Base64::enc(empty)), empty);

  constexpr char const* text_long
      = R"(Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus pretium ante placerat augue iaculis, consectetur commodo purus laoreet. Cras eu leo urna. Morbi sagittis nulla ut ipsum condimentum viverra. Vestibulum sed diam tortor. Maecenas consectetur scelerisque lorem, eu mollis felis tincidunt nec. Etiam ut ultricies elit. Maecenas pretium sit amet lectus sit amet semper. Sed lacinia dignissim nunc a viverra. Nunc at velit et ipsum malesuada tempor quis eu est. Aliquam egestas imperdiet purus, aliquet suscipit lectus. Nullam orci enim, egestas in felis a, sagittis egestas nulla. Nunc ultrices ultricies fringilla. Duis id tempor risus. In hac habitasse platea dictumst. Sed sit amet odio posuere, pretium sapien vel, dignissim velit.

Maecenas porttitor tincidunt libero, a lacinia ex pretium id. Proin venenatis non enim vel molestie. Sed finibus ornare arcu et bibendum. Vivamus est augue, facilisis sed ligula tempus, maximus pellentesque augue. Ut et sapien ac quam mattis lobortis eu eget neque. Morbi et malesuada leo, nec dignissim augue. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Morbi congue mi sed convallis ornare. Nam euismod dolor vel risus molestie bibendum. Sed iaculis, arcu sit amet tincidunt egestas, mi risus varius lorem, eu consequat velit ex id lacus. Proin condimentum porttitor arcu, et ullamcorper mauris iaculis vitae. Nullam porta lorem sapien, interdum euismod nibh accumsan quis. Aenean varius velit vitae ipsum pulvinar laoreet. Mauris sit amet leo quis arcu pellentesque placerat.

Nulla id quam velit. Cras semper euismod odio rhoncus gravida. Proin at varius enim. Suspendisse in quam tincidunt, aliquam lacus in, efficitur velit. Morbi et quam enim. Praesent placerat gravida efficitur. Aenean sit amet dolor arcu. Phasellus consequat erat risus, a varius turpis posuere ultrices. Pellentesque placerat lorem eu vulputate varius. Etiam consectetur pharetra ante, eu venenatis nulla congue et.

Sed et bibendum neque, in elementum odio. Phasellus in lobortis tellus. Mauris condimentum mi vel metus hendrerit, a accumsan neque pellentesque. Proin feugiat dui nec sem gravida, eu tincidunt metus dignissim. Nullam magna nisi, volutpat eget luctus nec, pulvinar sit amet lacus. Donec suscipit lectus magna, fringilla euismod arcu vehicula feugiat. Ut metus orci, interdum non purus in, lobortis egestas velit. Vestibulum dui eros, tincidunt ultrices mi vitae, tincidunt varius magna. Duis commodo convallis malesuada. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Pellentesque dictum tincidunt ligula et venenatis.

Nullam et neque eu diam blandit iaculis nec tincidunt magna. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Nunc eget iaculis tellus. Curabitur pretium, nisl ut tincidunt fringilla, diam orci imperdiet purus, ut sagittis arcu sapien at felis. Cras quis enim odio. Sed sed scelerisque elit. Integer laoreet quis nulla non tristique. Aenean sed scelerisque leo. Ut et mi a lacus fermentum commodo at ut ipsum. Aliquam nunc dolor, mollis ultricies dui in, efficitur elementum magna. Suspendisse eleifend augue sapien, non accumsan mi posuere ut.)";

  s = text_long;

  CHECK_EQ(Base64::dec(Base64::enc(s, 72)), s);
}

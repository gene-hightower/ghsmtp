#include "Base64.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  auto constexpr text{R"(
“We are all in the gutter, but some of us are looking at the stars.”
                                                     ― Oscar Wilde
)"};

  CHECK_EQ(Base64::dec(Base64::enc(text)), text);

  auto s{std::string{text}};

  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);
  s.pop_back();
  CHECK_EQ(Base64::dec(Base64::enc(s)), s);

  auto constexpr empty{""};
  CHECK_EQ(Base64::dec(Base64::enc(empty)), empty);

  auto constexpr text_long{
      R"(Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus pretium ante placerat augue iaculis, consectetur commodo purus laoreet. Cras eu leo urna. Morbi sagittis nulla ut ipsum condimentum viverra. Vestibulum sed diam tortor. Maecenas consectetur scelerisque lorem, eu mollis felis tincidunt nec. Etiam ut ultricies elit. Maecenas pretium sit amet lectus sit amet semper. Sed lacinia dignissim nunc a viverra. Nunc at velit et ipsum malesuada tempor quis eu est. Aliquam egestas imperdiet purus, aliquet suscipit lectus. Nullam orci enim, egestas in felis a, sagittis egestas nulla. Nunc ultrices ultricies fringilla. Duis id tempor risus. In hac habitasse platea dictumst. Sed sit amet odio posuere, pretium sapien vel, dignissim velit.

Maecenas porttitor tincidunt libero, a lacinia ex pretium id. Proin venenatis non enim vel molestie. Sed finibus ornare arcu et bibendum. Vivamus est augue, facilisis sed ligula tempus, maximus pellentesque augue. Ut et sapien ac quam mattis lobortis eu eget neque. Morbi et malesuada leo, nec dignissim augue. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Morbi congue mi sed convallis ornare. Nam euismod dolor vel risus molestie bibendum. Sed iaculis, arcu sit amet tincidunt egestas, mi risus varius lorem, eu consequat velit ex id lacus. Proin condimentum porttitor arcu, et ullamcorper mauris iaculis vitae. Nullam porta lorem sapien, interdum euismod nibh accumsan quis. Aenean varius velit vitae ipsum pulvinar laoreet. Mauris sit amet leo quis arcu pellentesque placerat.

Nulla id quam velit. Cras semper euismod odio rhoncus gravida. Proin at varius enim. Suspendisse in quam tincidunt, aliquam lacus in, efficitur velit. Morbi et quam enim. Praesent placerat gravida efficitur. Aenean sit amet dolor arcu. Phasellus consequat erat risus, a varius turpis posuere ultrices. Pellentesque placerat lorem eu vulputate varius. Etiam consectetur pharetra ante, eu venenatis nulla congue et.

Sed et bibendum neque, in elementum odio. Phasellus in lobortis tellus. Mauris condimentum mi vel metus hendrerit, a accumsan neque pellentesque. Proin feugiat dui nec sem gravida, eu tincidunt metus dignissim. Nullam magna nisi, volutpat eget luctus nec, pulvinar sit amet lacus. Donec suscipit lectus magna, fringilla euismod arcu vehicula feugiat. Ut metus orci, interdum non purus in, lobortis egestas velit. Vestibulum dui eros, tincidunt ultrices mi vitae, tincidunt varius magna. Duis commodo convallis malesuada. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Pellentesque dictum tincidunt ligula et venenatis.

Nullam et neque eu diam blandit iaculis nec tincidunt magna. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Nunc eget iaculis tellus. Curabitur pretium, nisl ut tincidunt fringilla, diam orci imperdiet purus, ut sagittis arcu sapien at felis. Cras quis enim odio. Sed sed scelerisque elit. Integer laoreet quis nulla non tristique. Aenean sed scelerisque leo. Ut et mi a lacus fermentum commodo at ut ipsum. Aliquam nunc dolor, mollis ultricies dui in, efficitur elementum magna. Suspendisse eleifend augue sapien, non accumsan mi posuere ut.)"};

  auto constexpr text_long_enc{
      R"(TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxp
dC4gUGhhc2VsbHVzIHByZXRpdW0gYW50ZSBwbGFjZXJhdCBhdWd1ZSBpYWN1bGlzLCBjb25z
ZWN0ZXR1ciBjb21tb2RvIHB1cnVzIGxhb3JlZXQuIENyYXMgZXUgbGVvIHVybmEuIE1vcmJp
IHNhZ2l0dGlzIG51bGxhIHV0IGlwc3VtIGNvbmRpbWVudHVtIHZpdmVycmEuIFZlc3RpYnVs
dW0gc2VkIGRpYW0gdG9ydG9yLiBNYWVjZW5hcyBjb25zZWN0ZXR1ciBzY2VsZXJpc3F1ZSBs
b3JlbSwgZXUgbW9sbGlzIGZlbGlzIHRpbmNpZHVudCBuZWMuIEV0aWFtIHV0IHVsdHJpY2ll
cyBlbGl0LiBNYWVjZW5hcyBwcmV0aXVtIHNpdCBhbWV0IGxlY3R1cyBzaXQgYW1ldCBzZW1w
ZXIuIFNlZCBsYWNpbmlhIGRpZ25pc3NpbSBudW5jIGEgdml2ZXJyYS4gTnVuYyBhdCB2ZWxp
dCBldCBpcHN1bSBtYWxlc3VhZGEgdGVtcG9yIHF1aXMgZXUgZXN0LiBBbGlxdWFtIGVnZXN0
YXMgaW1wZXJkaWV0IHB1cnVzLCBhbGlxdWV0IHN1c2NpcGl0IGxlY3R1cy4gTnVsbGFtIG9y
Y2kgZW5pbSwgZWdlc3RhcyBpbiBmZWxpcyBhLCBzYWdpdHRpcyBlZ2VzdGFzIG51bGxhLiBO
dW5jIHVsdHJpY2VzIHVsdHJpY2llcyBmcmluZ2lsbGEuIER1aXMgaWQgdGVtcG9yIHJpc3Vz
LiBJbiBoYWMgaGFiaXRhc3NlIHBsYXRlYSBkaWN0dW1zdC4gU2VkIHNpdCBhbWV0IG9kaW8g
cG9zdWVyZSwgcHJldGl1bSBzYXBpZW4gdmVsLCBkaWduaXNzaW0gdmVsaXQuCgpNYWVjZW5h
cyBwb3J0dGl0b3IgdGluY2lkdW50IGxpYmVybywgYSBsYWNpbmlhIGV4IHByZXRpdW0gaWQu
IFByb2luIHZlbmVuYXRpcyBub24gZW5pbSB2ZWwgbW9sZXN0aWUuIFNlZCBmaW5pYnVzIG9y
bmFyZSBhcmN1IGV0IGJpYmVuZHVtLiBWaXZhbXVzIGVzdCBhdWd1ZSwgZmFjaWxpc2lzIHNl
ZCBsaWd1bGEgdGVtcHVzLCBtYXhpbXVzIHBlbGxlbnRlc3F1ZSBhdWd1ZS4gVXQgZXQgc2Fw
aWVuIGFjIHF1YW0gbWF0dGlzIGxvYm9ydGlzIGV1IGVnZXQgbmVxdWUuIE1vcmJpIGV0IG1h
bGVzdWFkYSBsZW8sIG5lYyBkaWduaXNzaW0gYXVndWUuIE9yY2kgdmFyaXVzIG5hdG9xdWUg
cGVuYXRpYnVzIGV0IG1hZ25pcyBkaXMgcGFydHVyaWVudCBtb250ZXMsIG5hc2NldHVyIHJp
ZGljdWx1cyBtdXMuIE1vcmJpIGNvbmd1ZSBtaSBzZWQgY29udmFsbGlzIG9ybmFyZS4gTmFt
IGV1aXNtb2QgZG9sb3IgdmVsIHJpc3VzIG1vbGVzdGllIGJpYmVuZHVtLiBTZWQgaWFjdWxp
cywgYXJjdSBzaXQgYW1ldCB0aW5jaWR1bnQgZWdlc3RhcywgbWkgcmlzdXMgdmFyaXVzIGxv
cmVtLCBldSBjb25zZXF1YXQgdmVsaXQgZXggaWQgbGFjdXMuIFByb2luIGNvbmRpbWVudHVt
IHBvcnR0aXRvciBhcmN1LCBldCB1bGxhbWNvcnBlciBtYXVyaXMgaWFjdWxpcyB2aXRhZS4g
TnVsbGFtIHBvcnRhIGxvcmVtIHNhcGllbiwgaW50ZXJkdW0gZXVpc21vZCBuaWJoIGFjY3Vt
c2FuIHF1aXMuIEFlbmVhbiB2YXJpdXMgdmVsaXQgdml0YWUgaXBzdW0gcHVsdmluYXIgbGFv
cmVldC4gTWF1cmlzIHNpdCBhbWV0IGxlbyBxdWlzIGFyY3UgcGVsbGVudGVzcXVlIHBsYWNl
cmF0LgoKTnVsbGEgaWQgcXVhbSB2ZWxpdC4gQ3JhcyBzZW1wZXIgZXVpc21vZCBvZGlvIHJo
b25jdXMgZ3JhdmlkYS4gUHJvaW4gYXQgdmFyaXVzIGVuaW0uIFN1c3BlbmRpc3NlIGluIHF1
YW0gdGluY2lkdW50LCBhbGlxdWFtIGxhY3VzIGluLCBlZmZpY2l0dXIgdmVsaXQuIE1vcmJp
IGV0IHF1YW0gZW5pbS4gUHJhZXNlbnQgcGxhY2VyYXQgZ3JhdmlkYSBlZmZpY2l0dXIuIEFl
bmVhbiBzaXQgYW1ldCBkb2xvciBhcmN1LiBQaGFzZWxsdXMgY29uc2VxdWF0IGVyYXQgcmlz
dXMsIGEgdmFyaXVzIHR1cnBpcyBwb3N1ZXJlIHVsdHJpY2VzLiBQZWxsZW50ZXNxdWUgcGxh
Y2VyYXQgbG9yZW0gZXUgdnVscHV0YXRlIHZhcml1cy4gRXRpYW0gY29uc2VjdGV0dXIgcGhh
cmV0cmEgYW50ZSwgZXUgdmVuZW5hdGlzIG51bGxhIGNvbmd1ZSBldC4KClNlZCBldCBiaWJl
bmR1bSBuZXF1ZSwgaW4gZWxlbWVudHVtIG9kaW8uIFBoYXNlbGx1cyBpbiBsb2JvcnRpcyB0
ZWxsdXMuIE1hdXJpcyBjb25kaW1lbnR1bSBtaSB2ZWwgbWV0dXMgaGVuZHJlcml0LCBhIGFj
Y3Vtc2FuIG5lcXVlIHBlbGxlbnRlc3F1ZS4gUHJvaW4gZmV1Z2lhdCBkdWkgbmVjIHNlbSBn
cmF2aWRhLCBldSB0aW5jaWR1bnQgbWV0dXMgZGlnbmlzc2ltLiBOdWxsYW0gbWFnbmEgbmlz
aSwgdm9sdXRwYXQgZWdldCBsdWN0dXMgbmVjLCBwdWx2aW5hciBzaXQgYW1ldCBsYWN1cy4g
RG9uZWMgc3VzY2lwaXQgbGVjdHVzIG1hZ25hLCBmcmluZ2lsbGEgZXVpc21vZCBhcmN1IHZl
aGljdWxhIGZldWdpYXQuIFV0IG1ldHVzIG9yY2ksIGludGVyZHVtIG5vbiBwdXJ1cyBpbiwg
bG9ib3J0aXMgZWdlc3RhcyB2ZWxpdC4gVmVzdGlidWx1bSBkdWkgZXJvcywgdGluY2lkdW50
IHVsdHJpY2VzIG1pIHZpdGFlLCB0aW5jaWR1bnQgdmFyaXVzIG1hZ25hLiBEdWlzIGNvbW1v
ZG8gY29udmFsbGlzIG1hbGVzdWFkYS4gT3JjaSB2YXJpdXMgbmF0b3F1ZSBwZW5hdGlidXMg
ZXQgbWFnbmlzIGRpcyBwYXJ0dXJpZW50IG1vbnRlcywgbmFzY2V0dXIgcmlkaWN1bHVzIG11
cy4gUGVsbGVudGVzcXVlIGRpY3R1bSB0aW5jaWR1bnQgbGlndWxhIGV0IHZlbmVuYXRpcy4K
Ck51bGxhbSBldCBuZXF1ZSBldSBkaWFtIGJsYW5kaXQgaWFjdWxpcyBuZWMgdGluY2lkdW50
IG1hZ25hLiBWZXN0aWJ1bHVtIGFudGUgaXBzdW0gcHJpbWlzIGluIGZhdWNpYnVzIG9yY2kg
bHVjdHVzIGV0IHVsdHJpY2VzIHBvc3VlcmUgY3ViaWxpYSBDdXJhZTsgTnVuYyBlZ2V0IGlh
Y3VsaXMgdGVsbHVzLiBDdXJhYml0dXIgcHJldGl1bSwgbmlzbCB1dCB0aW5jaWR1bnQgZnJp
bmdpbGxhLCBkaWFtIG9yY2kgaW1wZXJkaWV0IHB1cnVzLCB1dCBzYWdpdHRpcyBhcmN1IHNh
cGllbiBhdCBmZWxpcy4gQ3JhcyBxdWlzIGVuaW0gb2Rpby4gU2VkIHNlZCBzY2VsZXJpc3F1
ZSBlbGl0LiBJbnRlZ2VyIGxhb3JlZXQgcXVpcyBudWxsYSBub24gdHJpc3RpcXVlLiBBZW5l
YW4gc2VkIHNjZWxlcmlzcXVlIGxlby4gVXQgZXQgbWkgYSBsYWN1cyBmZXJtZW50dW0gY29t
bW9kbyBhdCB1dCBpcHN1bS4gQWxpcXVhbSBudW5jIGRvbG9yLCBtb2xsaXMgdWx0cmljaWVz
IGR1aSBpbiwgZWZmaWNpdHVyIGVsZW1lbnR1bSBtYWduYS4gU3VzcGVuZGlzc2UgZWxlaWZl
bmQgYXVndWUgc2FwaWVuLCBub24gYWNjdW1zYW4gbWkgcG9zdWVyZSB1dC4=)"};

  CHECK_EQ(Base64::dec(text_long_enc), text_long);
  CHECK_EQ(Base64::dec(Base64::enc(text_long, 72)), text_long);
}

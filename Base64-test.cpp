#include "Base64.hpp"

#include <glog/logging.h>

int main(int argc, char* argv[])
{
  constexpr char const* text = R"xxyyzz(
The Fat Man design was tested in the Trinity nuclear test in July
1945. Project Y personnel formed pit crews and assembly teams for the
bombing of Hiroshima and Nagasaki and participated in the bombing as
weaponeers and observers. After the war ended, the laboratory
supported the Operation Crossroads nuclear tests at Bikini Atoll. A
new Z Division was created to control testing, stockpiling and bomb
assembly activities, which were concentrated at Sandia Base. The Los
Alamos Laboratory became Los Alamos Scientific Laboratory in 1947.
)xxyyzz";

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
}

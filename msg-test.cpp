#define main no_main
#include "msg.cpp"
#undef main

int main()
{
  CHECK(RFC5322::is_defined_field("Subject"));
  CHECK(!RFC5322::is_defined_field("X-Subject"));

  const char* ip_list[]{
      "2607:f8b0:4001:c0b::22a", "127.0.0.1",
  };

  for (auto i : ip_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx ctx;
    if (!parse<RFC5322::ip, RFC5322::action /*, tao::pegtl::tracer*/>(in,
                                                                      ctx)) {
      LOG(ERROR) << "Error parsing as ip \"" << i << "\"";
    }
  }

  const char* rec_list[]{
      // github
      "Received: from github-smtp2a-ext-cp1-prd.iad.github.net "
      "(github-smtp2a-ext-cp1-prd.iad.github.net [192.30.253.16])\r\n"
      " by ismtpd0004p1iad1.sendgrid.net (SG) with ESMTP id "
      "OCAkwxSQQTiPcF-T3rLS3w\r\n"
      "	for <gene-github@digilicious.com>; Tue, 23 May 2017 "
      "23:01:49.124 +0000 (UTC)\r\n",

      // sendgrid date is shit
      // "Received: by filter0810p1mdw1.sendgrid.net with SMTP id "
      // "filter0810p1mdw1-13879-5924BDA5-34\r\n"
      // "        2017-05-23 22:54:29.679063164 +0000 UTC\r\n",

  };

  for (auto i : rec_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx ctx;
    if (!parse<RFC5322::received, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Received: \"" << i << "\"";
    }
  }

  const char* date_list[]{
      "Date: Tue, 30 May 2017 10:52:11 +0000 (UTC)\r\n",
      "Date: Mon, 29 May 2017 16:47:58 -0700\r\n",

      // this date is shit
      // "Date: Mon, 29 May 2017 19:47:08 EDT\r\n",
  };

  for (auto i : date_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx ctx;
    if (!parse<RFC5322::orig_date, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Date: \"" << i << "\"";
    }
  }

  const char* spf_list[]{
      // works
      "Received-SPF: pass (digilicious.com: domain of gmail.com designates "
      "74.125.82.46 as permitted sender) client-ip=74.125.82.46; "
      "envelope-from=sclark0322@gmail.com; helo=mail-wm0-f46.google.com;\r\n",

      // also works
      "Received-SPF: neutral (google.com: 2607:f8b0:4001:c0b::22a is neither "
      "permitted nor denied by best guess record for domain of "
      "rickoco@riscv.org) client-ip=2607:f8b0:4001:c0b::22a;\r\n",
  };

  for (auto i : spf_list) {
    memory_input<> in(i, i);
    RFC5322::Ctx ctx;
    if (!parse<RFC5322::received_spf, RFC5322::action /*, tao::pegtl::tracer*/>(
            in, ctx)) {
      LOG(ERROR) << "Error parsing as Received-SPF: \"" << i << "\"";
    }
  }
}


int main()
{
  auto read_hook = []() {};
  static RFC5321::Connection cnn(0, 1, read_hook);

  const char* greet_list[]{
      "220-mtaig-aak03.mx.aol.com ESMTP Internet Inbound\r\n"
      "220-AOL and its affiliated companies do not\r\n"
      "220-authorize the use of its proprietary computers and computer\r\n"
      "220-networks to accept, transmit, or distribute unsolicited bulk\r\n"
      "220-e-mail sent from the internet.\r\n"
      "220-Effective immediately:\r\n"
      "220-AOL may no longer accept connections from IP addresses\r\n"
      "220 which no do not have reverse-DNS (PTR records) assigned.\r\n"};

  for (auto i : greet_list) {
    memory_input<> in(i, i);
    if (!parse<RFC5321::greeting, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing greeting \"" << i << "\"";
    }
  }

  const char* ehlo_rsp_list[]{
      "250-digilicious.com at your service, localhost. [IPv6:::1]\r\n"
      "250-SIZE 15728640\r\n"
      "250-8BITMIME\r\n"
      "250-STARTTLS\r\n"
      "250-ENHANCEDSTATUSCODES\r\n"
      "250-PIPELINING\r\n"
      "250-BINARYMIME\r\n"
      "250-CHUNKING\r\n"
      "250 SMTPUTF8\r\n",
      "500 5.5.1 command unrecognized: \"EHLO digilicious.com\\r\\n\"\r\n",
  };

  for (auto i : ehlo_rsp_list) {
    memory_input<> in(i, i);
    if (!parse<RFC5321::ehlo_rsp, RFC5321::action /*, tao::pegtl::tracer*/>(
            in, cnn)) {
      LOG(FATAL) << "Error parsing ehlo response \"" << i << "\"";
    }
  }
}

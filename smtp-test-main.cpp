int main()
{
  const char* good_list[]{
      "anything\r\n"
      ".\r\n", // end

      "anything\r\n"
      "..anything\r\n"
      ".\r\n", // end

      "anything\r\n"
      "\nanything\r\n"
      "\ranything\r\n"
      "anything\r\n"
      ".\r\n", // end
  };

  const char* bad_list[]{
      ".anything\r\n",

      "anything\r\n"
      "anything\r\n"
      "anything\r\n"
      "anything\r\n"
      "anything\r\n",

      "anything",  // no CRLF
      ".anything", // no CRLF

      "",

  };

  for (auto i : good_list) {
    std::string bfr(i);
    std::istringstream data(bfr);
    istream_input<eol::crlf> in(data, Config::bfr_size, "data");
    RFC5321::Ctx ctx;
    if (!parse<RFC5321::data_grammar, RFC5321::data_action>(in, ctx)) {
      LOG(FATAL) << "\"" << esc(i) << "\"";
    }
  }
  for (auto i : bad_list) {
    std::string bfr(i);
    std::istringstream data(bfr);
    istream_input<eol::crlf> in(data, Config::bfr_size, "data");
    RFC5321::Ctx ctx;
    if (parse<RFC5321::data_grammar, RFC5321::data_action>(in, ctx)) {
      LOG(FATAL) << "\"" << esc(i) << "\"";
    }
  }
}

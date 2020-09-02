#include "rewrite.hpp"

#include "ARC.hpp"
#include "esc.hpp"
#include "imemstream.hpp"

#include <cstring>

#include <boost/iostreams/device/mapped_file.hpp>

static void do_arc(char const* dom, char const* msg, size_t len)
{
  ARC::lib arc;

  char const* error = nullptr;

  auto arc_msg = arc.message(ARC_CANON_SIMPLE, ARC_CANON_RELAXED,
                             ARC_SIGN_RSASHA256, ARC_MODE_SIGN, &error);

  imemstream  stream{msg, len};
  std::string header;
  std::string line;
  while (std::getline(stream, line)) {
    if (!stream.eof() && !stream.fail()) {
      line.push_back('\n');
    }
    if (line[0] == ' ' || line[0] == '\t') {
      header += line;
    }
    else {
      if (!header.empty()) {
        LOG(INFO) << "header «" << esc(header, esc_line_option::multi) << "»";
        CHECK_EQ(arc_msg.header_field(line.data(), line.length()), ARC_STAT_OK)
          << arc_msg.geterror();
      }
      if (line == "\r\n") {
        CHECK_EQ(arc_msg.eoh(), ARC_STAT_OK) << arc_msg.geterror();
        break;
      }
      header = line;
    }
  }
  // body
  while (std::getline(stream, line)) {
    if (!stream.eof() && !stream.fail()) {
      line.push_back('\n');
    }
    CHECK_EQ(arc_msg.body(line.data(), line.length()), ARC_STAT_OK)
        << arc_msg.geterror();
  }
  CHECK_EQ(arc_msg.eom(), ARC_STAT_OK) << arc_msg.geterror();

  boost::iostreams::mapped_file_source priv;
  priv.open("ghsmtp.private");

  ARC_HDRFIELD* seal = nullptr;

  CHECK_EQ(arc_msg.seal(&seal, dom, "arc", dom, priv.data(), priv.size(), ""),
           ARC_STAT_OK)
      << arc_msg.geterror();

  if (seal) {
    auto const nam = ARC::hdr::name(seal);
    auto const val = ARC::hdr::value(seal);
    LOG(INFO) << nam << ": " << val;
  }
  else {
    LOG(INFO) << "no seal";
  }
}

std::pair<std::unique_ptr<char[]>, size_t>
rewrite(char const* dom, char const* dp_in, size_t length_in)
{
  do_arc(dom, dp_in, length_in);

  auto dp = std::make_unique<char[]>(length_in);
  std::memcpy(dp.get(), dp_in, length_in);
  return std::pair{std::move(dp), length_in};
}

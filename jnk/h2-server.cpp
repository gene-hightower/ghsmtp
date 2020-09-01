#include <iostream>

#include <nghttp2/asio_http2_server.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

int main(int argc, char* argv[])
{
  boost::system::error_code ec;
  boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);

  tls.use_private_key_file("smtp.key", boost::asio::ssl::context::pem);
  tls.use_certificate_chain_file("smtp.pem");

  configure_tls_context_easy(ec, tls);

  http2 server;

  server.handle("/index.html", [](const request& req, const response& res) {
    res.write_head(200);
    res.end(file_generator("index.html"));
  });

  if (server.listen_and_serve(ec, tls, "localhost", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}

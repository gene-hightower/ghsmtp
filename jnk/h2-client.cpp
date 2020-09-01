#include <iostream>

#include <gflags/gflags.h>

#include <fmt/format.h>

#include <nghttp2/asio_http2_client.h>

using boost::asio::ip::tcp;

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;

int main(int argc, char* argv[])
{
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  boost::system::error_code ec;
  boost::asio::io_service   io_service;

  boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
  tls.set_default_verify_paths();

  tls.set_verify_mode(boost::asio::ssl::verify_peer);

  configure_tls_context(ec, tls);

  for (int i = 1; i < argc; ++i) {
    auto constexpr domain = argv[i];

    session sess(io_service, tls, server, port);

    sess.on_connect(
        [&server, &port, &sess](tcp::resolver::iterator endpoint_it) {
          boost::system::error_code ec;

          auto const url
              = fmt::format("https://{}/.well-known/mta-sts.txt", server);

          auto req = sess.submit(ec, "GET", url);

          req->on_response([&sess](const response& res) {
            res.on_data([&sess](const uint8_t* data, std::size_t len) {
              std::cout.write(reinterpret_cast<const char*>(data), len);
            });
          });

          // req->on_push([](const request& push) {
          //   std::cerr << "push request received!" << std::endl;
          //   push.on_response([](const response& res) {
          //     std::cerr << "push response received!" << std::endl;
          //     res.on_data([](const uint8_t* data, std::size_t len) {
          //       std::cout.write(reinterpret_cast<const char*>(data), len);
          //       std::cout << '\n';
          //     });
          //   });
          // });
        });

    sess.on_error([](const boost::system::error_code& ec) {
      std::cerr << "error: " << ec.message() << std::endl;
    });

    io_service.run();

    return EXIT_SUCCESS;
  }

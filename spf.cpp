#include <iostream>

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include <spf2/spf.h>
}

#include "Logging.hpp"

// We map libspf2's levels of error, warning, info and debug to
// Google's fatal, error, warning and info.

void glog_error(const char* file, int line, char const* errmsg)
{
  google::LogMessageFatal(file, line).stream() << errmsg;
}
void glog_warning(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line, google::GLOG_ERROR).stream() << errmsg;
}
void glog_info(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line, google::GLOG_WARNING).stream() << errmsg;
}
void glog_debug(const char* file, int line, char const* errmsg)
{
  google::LogMessage(file, line).stream() << errmsg;
}

int main(int argc, char const* argv[])
{
  Logging::init(argv[0]);

  SPF_error_handler = glog_error;
  SPF_warning_handler = glog_warning;
  SPF_info_handler = glog_info;
  SPF_debug_handler = glog_debug;

  SPF_server_t* spf_server = CHECK_NOTNULL(SPF_server_new(SPF_DNS_RESOLV, 1));
  SPF_request_t* spf_request = CHECK_NOTNULL(SPF_request_new(spf_server));

  SPF_server_set_rec_dom(spf_server, "EXAMPLE.COM");

  if (SPF_request_set_ipv4_str(spf_request, "162.217.145.172")) {
    printf("Invalid IP address.\n");
    exit(1);
  }

  if (SPF_request_set_helo_dom(spf_request, "mail.pak-dota2.com")) {
    printf("Invalid HELO domain.\n");
    exit(2);
  }

  if (SPF_request_set_env_from(
          spf_request, "reagans_nina-admin=digilicious.com@pak-dota2.xcom")) {
    printf("Invalid envelope from address.\n");
    exit(3);
  }

  SPF_response_t* spf_response = NULL;
  SPF_response_t* spf_response_2mx = NULL;

  SPF_request_query_mailfrom(spf_request, &spf_response);
  if (SPF_response_result(spf_response) != SPF_RESULT_PASS) {
    SPF_request_query_rcptto(spf_request, &spf_response_2mx,
                             "gene@digilicious.com");
    if (SPF_response_result(spf_response_2mx) != SPF_RESULT_PASS) {
      std::cout << "fail" << std::endl;
    }
  }

  std::cout << "str == " << SPF_strresult(SPF_response_result(spf_response))
            << std::endl;

  if (SPF_response_get_smtp_comment(spf_response)) {
    std::cout << "smtp comment == "
              << SPF_response_get_smtp_comment(spf_response) << std::endl;
  }
  if (SPF_response_get_header_comment(spf_response)) {
    std::cout << "header comment == "
              << SPF_response_get_header_comment(spf_response) << std::endl;
  }
  if (SPF_response_get_received_spf(spf_response)) {
    std::cout << "received spf == "
              << SPF_response_get_received_spf(spf_response) << std::endl;
  }

  SPF_response_free(spf_response);
  if (spf_response_2mx)
    SPF_response_free(spf_response_2mx);

  if (spf_request)
    SPF_request_free(spf_request);
  if (spf_server)
    SPF_server_free(spf_server);
}

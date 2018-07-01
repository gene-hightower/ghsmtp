#ifndef SPF_DOT_HPP
#define SPF_DOT_HPP

#include <ostream>

#include <glog/logging.h>

// forward stuff from <spf2/spf.h>
typedef struct SPF_server_struct SPF_server_t;
typedef struct SPF_request_struct SPF_request_t;
typedef struct SPF_response_struct SPF_response_t;

namespace SPF {

class Result {
public:
  Result() = default;
  Result(int value); // int for SPF_result_t

  enum class value_t {
    INVALID,
    NEUTRAL,
    PASS,
    FAIL,
    SOFTFAIL,
    NONE,
    TEMPERROR,
    PERMERROR,
  };

  // clang-format off
  static constexpr auto INVALID   = value_t::INVALID;
  static constexpr auto NEUTRAL   = value_t::NEUTRAL;
  static constexpr auto PASS      = value_t::PASS;
  static constexpr auto FAIL      = value_t::FAIL;
  static constexpr auto SOFTFAIL  = value_t::SOFTFAIL;
  static constexpr auto NONE      = value_t::NONE;
  static constexpr auto TEMPERROR = value_t::TEMPERROR;
  static constexpr auto PERMERROR = value_t::PERMERROR;
  // clang-format on

  static char const* c_str(value_t value);

  char const* c_str() const { return c_str(value_); }

  operator value_t() const { return value_; }
  explicit operator char const*() const { return c_str(); }

private:
  value_t value_{INVALID};
};

std::ostream& operator<<(std::ostream& os, Result result);
std::ostream& operator<<(std::ostream& os, Result::value_t result);

class Server {
public:
  Server(Server const&) = delete;
  Server& operator=(Server const&) = delete;

  explicit Server(char const* fqdn);
  ~Server();

  static class initializer {
  public:
    initializer();
  } init;

private:
  SPF_server_t* srv_{nullptr};

  // We map libspf2's levels of error, warning, info and debug to our
  // own fatal, error, warning and info log levels.
  static void log_error_(const char* file, int line, char const* errmsg)
      __attribute__((noreturn))
  {
    LOG(FATAL) << file << ":" << line << " " << errmsg;
  }
  static void log_warning_(const char* file, int line, char const* errmsg)
  {
    LOG(WARNING) << file << ":" << line << " " << errmsg;
  }
  static void log_info_(const char* file, int line, char const* errmsg)
  {
    LOG(INFO) << file << ":" << line << " " << errmsg;
  }

  friend class Request;
};

class Request {
public:
  Request(Request const&) = delete;
  Request& operator=(Request const&) = delete;

  Request()
    : req_(nullptr)
  {
  }
  explicit Request(Server const& srv);

  Request(Request&& other)
    : req_(other.req_)
  {
    other.req_ = nullptr;
  }
  Request& operator=(Request&& other)
  {
    if (this != &other) { // prevent self-move
      CHECK((req_ == nullptr) || (req_ == other.req_))
          << "can only move into default constructed object";
      req_ = other.req_;
      other.req_ = nullptr;
    }
    return *this;
  }

  ~Request();

  void set_ip_str(char const* ip);
  void set_ipv4_str(char const* ipv4);
  void set_ipv6_str(char const* ipv6);
  void set_helo_dom(char const* dom);
  void set_env_from(char const* frm);
  char const* get_sender_dom() const;

private:
  SPF_request_t* req_{nullptr};

  friend class Response;
};

class Response {
public:
  Response(Response const&) = delete;
  Response& operator=(Response const&) = delete;

  Response();
  explicit Response(Request const& req);

  Response(Response&& other)
    : res_(other.res_)
  {
    other.res_ = nullptr;
  }
  Response& operator=(Response&& other)
  {
    if (this != &other) { // prevent self-move
      CHECK(res_ == nullptr) << "can only move into default constructed object";
      res_ = other.res_;
      other.res_ = nullptr;
    }
    return *this;
  }

  ~Response();

  Result result() const;
  char const* smtp_comment() const;
  char const* header_comment() const;
  char const* received_spf() const;

private:
  SPF_response_t* res_{nullptr};
};

} // namespace SPF

#endif // SPF_DOT_HPP

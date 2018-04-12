#include <chrono>
#include <functional>
#include <iomanip>
#include <regex>
#include <string>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <glog/logging.h>

#include "DNS.hpp"
#include "POSIX.hpp"
#include "TLS-OpenSSL.hpp"
#include "osutil.hpp"

// <https://tools.ietf.org/html/rfc7919>
// <https://wiki.mozilla.org/Security/Server_Side_TLS#DHE_handshake_and_dhparam>
constexpr char ffdhe4096[] = R"(
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----
)";

// convert binary input into a std::string of hex digits

auto bin2hexstring(uint8_t const* data, size_t length)
{
  std::string ret;
  ret.reserve(2 * length + 1);

  for (size_t n = 0u; n < length; ++n) {
    auto const ch = data[n];

    auto const lo = ch & 0xF;
    auto const hi = (ch >> 4) & 0xF;

    auto constexpr hex_digits = "0123456789abcdef";

    ret += hex_digits[hi];
    ret += hex_digits[lo];
  }

  return ret;
}

auto list_directory(fs::path const& path, std::string const& pattern)
{
  std::vector<fs::path> ret;

#if defined(__APPLE__) || defined(_WIN32)
  auto const traits
      = std::regex_constants::ECMAScript | std::regex_constants::icase;
#else
  auto const traits = std::regex_constants::ECMAScript;
#endif

  std::regex const pattern_regex(pattern, traits);

  for (auto const& it : fs::directory_iterator(path)) {
    auto const it_filename = it.path().filename().string();
    std::smatch matches;
    if (std::regex_match(it_filename, matches, pattern_regex)) {
      ret.push_back(it.path());
    }
  }

  return ret;
}

TLS::TLS(std::function<void(void)> read_hook)
  : read_hook_(read_hook)
{
}

TLS::~TLS()
{
  for (auto&& ctx : cert_ctx_) {
    if (ctx.ctx) {
      SSL_CTX_free(ctx.ctx);
    }
  }
  if (ssl_) {
    SSL_free(ssl_);
  }
}

struct session_context {
};

static int session_context_index = -1;

static int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
  auto const cert = X509_STORE_CTX_get_current_cert(ctx);
  if (cert == nullptr)
    return 1;

  auto err = X509_STORE_CTX_get_error(ctx);

  auto const ssl = reinterpret_cast<SSL*>(
      X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));

  CHECK_GE(session_context_index, 0);

  auto const unused = reinterpret_cast<session_context*>(
      SSL_get_ex_data(ssl, session_context_index));

  auto const depth = X509_STORE_CTX_get_error_depth(ctx);

  char buf[256];
  X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));

  if (depth > Config::cert_verify_depth) {
    preverify_ok = 0;
    err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(ctx, err);
  }
  if (!preverify_ok) {
    LOG(INFO) << "verify error:num=" << err << ':'
              << X509_verify_cert_error_string(err) << ": depth=" << depth
              << ':' << buf;
  }
  else {
    LOG(INFO) << "preverify_ok; depth=" << depth << " subject_name=«" << buf
              << "»";
  }

  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
    if (cert) {
      X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
      LOG(INFO) << "issuer=" << buf;
    }
    else {
      LOG(INFO) << "issuer=<unknown>";
    }
  }

  return 1; // always continue
}

static int ssl_servername_callback(SSL* s, int* ad, void* arg)
{
  auto cert_ctx = static_cast<std::vector<TLS::per_cert_ctx>*>(arg);

  auto const servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  if (servername && *servername) {
    LOG(INFO) << "servername requested " << servername;
    for (auto const& ctx : *cert_ctx) {
      if (auto&& c = std::find(ctx.cn.begin(), ctx.cn.end(), servername);
          c != ctx.cn.end()) {
        LOG(INFO) << "found match, switching context";
        SSL_set_SSL_CTX(s, ctx.ctx);
        return SSL_TLSEXT_ERR_OK;
      }
    }
    LOG(INFO) << "servername not found";
  }

  return SSL_TLSEXT_ERR_ALERT_WARNING;
}

bool TLS::starttls_client(int fd_in,
                          int fd_out,
                          char const* hostname,
                          uint16_t port,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  auto const method = CHECK_NOTNULL(SSLv23_client_method());

  {
    auto ctx = CHECK_NOTNULL(SSL_CTX_new(method));
    std::vector<Domain> cn;

    // SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    CHECK_GT(SSL_CTX_dane_enable(ctx), 0)
        << "unable to enable DANE on SSL context";

    // you'd think if it's the default, you'd not have to call this
    CHECK_EQ(SSL_CTX_set_default_verify_paths(ctx), 1);

    auto const config_path = osutil::get_config_dir();

    auto const cert_path = config_path / Config::cert_fn;
    CHECK(fs::exists(cert_path)) << "can't find cert chain file " << cert_path;
    auto const& cert_path_str = cert_path.string();

    CHECK(SSL_CTX_use_certificate_chain_file(ctx, cert_path_str.c_str()) > 0)
        << "Can't load certificate chain file \"" << cert_path << "\"";

    auto const key_path = config_path / Config::key_fn;
    CHECK(fs::exists(key_path)) << "can't find key file " << key_path;
    auto const key_path_str = key_path.string();

    CHECK(
        SSL_CTX_use_PrivateKey_file(ctx, key_path_str.c_str(), SSL_FILETYPE_PEM)
        > 0)
        << "Can't load private key file \"" << key_path_str << "\"";

    CHECK(SSL_CTX_check_private_key(ctx))
        << "Private key does not match the public certificate";

    SSL_CTX_set_verify_depth(ctx, Config::cert_verify_depth + 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       verify_callback);

    cert_ctx_.emplace_back(ctx, cn);
  }

  ssl_ = CHECK_NOTNULL(SSL_new(cert_ctx_.back().ctx));

  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  std::ostringstream tlsa;

  tlsa << '_' << port << "._tcp." << hostname;

  DNS::Resolver res;
  DNS::Query q(res, DNS::RR_type::TLSA, DNS::Domain(tlsa.str()));

  if (q.nx_domain()) {
    LOG(INFO) << "TLSA data not found";
  }

  if (q.bogus_or_indeterminate()) {
    LOG(WARNING) << "TLSA data bogus_or_indeterminate";
  }

  DNS::RR_list rrlst(q);

  auto tlsa_rrs = rrlst.get_records();

  LOG(INFO) << "tlsa_rrs.size() == " << tlsa_rrs.size();

  if (tlsa_rrs.size()) {
    if (!q.authentic_data()) {
      LOG(ERROR) << "TLSA meaningless without DNSSEC";
    }

    CHECK_GE(SSL_dane_enable(ssl_, hostname), 0) << "SSL_dane_enable() failed";
    LOG(INFO) << "SSL_dane_enable(ssl_, " << hostname << ")";
  }
  else {
    CHECK_EQ(SSL_set1_host(ssl_, hostname), 1);

    // SSL_set_tlsext_host_name(ssl_, hostname);
    // same as:
    CHECK_EQ(SSL_ctrl(ssl_, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                      TLSEXT_NAMETYPE_host_name, const_cast<char*>(hostname)),
             1);
    LOG(INFO) << "SSL_set1_host and SSL_set_tlsext_host_name " << hostname
              << ")";
  }

  // No partial label wildcards
  SSL_set_hostflags(ssl_, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

  auto usable_TLSA_records = 0;

  for (auto const& tlsa_rr : tlsa_rrs) {
    if (std::holds_alternative<DNS::RR_TLSA>(tlsa_rr)) {
      auto const rp = std::get<DNS::RR_TLSA>(tlsa_rr);
      auto data = rp.assoc_data();
      auto rc = SSL_dane_tlsa_add(ssl_, rp.cert_usage(), rp.selector(),
                                  rp.matching_type(), data.data(), data.size());

      if (rc < 0) {
        auto const cp = bin2hexstring(data.data(), data.size());
        LOG(ERROR) << "SSL_dane_tlsa_add() failed.";
        LOG(ERROR) << "failed record: " << rp.cert_usage() << " "
                   << rp.selector() << " " << rp.matching_type() << " " << cp;
      }
      else if (rc == 0) {
        auto const cp = bin2hexstring(data.data(), data.size());
        LOG(ERROR) << "unusable TLSA record: " << rp.cert_usage() << " "
                   << rp.selector() << " " << rp.matching_type() << " " << cp;
      }
      else {
        // auto const cp = bin2hexstring(data.data(), data.size());
        // LOG(INFO) << "added TLSA record: " << rp.cert_usage() << " "
        //           << rp.selector() << " " << rp.matching_type() << " " << cp;
        ++usable_TLSA_records;
      }
    }
  }

  // CHECK_EQ(SSL_set_tlsext_host_name(ssl_, hostname), 1);
  // same as:
  // CHECK_EQ(SSL_ctrl(ssl_, SSL_CTRL_SET_TLSEXT_HOSTNAME,
  //                   TLSEXT_NAMETYPE_host_name, const_cast<char*>(hostname)),
  //          1);
  // LOG(INFO) << "SSL_set_tlsext_host_name == " << hostname;

  if (session_context_index < 0) {
    session_context_index
        = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  session_context context;
  SSL_set_ex_data(ssl_, session_context_index, &context);

  using namespace std::chrono;
  auto start = system_clock::now();

  ERR_clear_error();

  int rc;
  while ((rc = SSL_connect(ssl_)) < 0) {

    auto now = system_clock::now();

    CHECK(now < (start + timeout)) << "starttls timed out";

    auto time_left = duration_cast<milliseconds>((start + timeout) - now);

    switch (SSL_get_error(ssl_, rc)) {
    case SSL_ERROR_WANT_READ:
      CHECK(POSIX::input_ready(fd_in, time_left))
          << "starttls timed out on input_ready";
      ERR_clear_error();
      continue; // try SSL_accept again

    case SSL_ERROR_WANT_WRITE:
      CHECK(POSIX::output_ready(fd_out, time_left))
          << "starttls timed out on output_ready";
      ERR_clear_error();
      continue; // try SSL_accept again

    case SSL_ERROR_SYSCALL:
      LOG(WARNING) << "errno == " << errno << ": " << strerror(errno);
      [[fallthrough]];

    default:
      ssl_error();
      return false;
    }
  }

  if (SSL_get_verify_result(ssl_) == X509_V_OK) {
    LOG(INFO) << "server certificate verified";
    verified_ = true;

    char const* const peername = SSL_get0_peername(ssl_);
    if (peername != nullptr) {
      // Name checks were in scope and matched the peername
      LOG(INFO) << "verified peername: " << peername;
    }
    else {
      LOG(INFO) << "no verified peername";
    }

    EVP_PKEY* mspki = nullptr;
    int depth = SSL_get0_dane_authority(ssl_, nullptr, &mspki);
    if (depth >= 0) {

      uint8_t usage, selector, mtype;
      const unsigned char* certdata;
      size_t certdata_len;

      SSL_get0_dane_tlsa(ssl_, &usage, &selector, &mtype, &certdata,
                         &certdata_len);

      LOG(INFO) << "DANE TLSA " << unsigned(usage) << " " << unsigned(selector)
                << " " << unsigned(mtype) << " [" << bin2hexstring(certdata, 6)
                << "...] "
                << ((mspki != nullptr) ? "TA public key verified certificate"
                                       : depth ? "matched TA certificate"
                                               : "matched EE certificate")
                << " at depth " << depth;
    }
  }
  else {
    LOG(WARNING) << "server certificate failed to verify";
  }

  return true;
}

bool TLS::starttls_server(int fd_in,
                          int fd_out,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  auto const method = CHECK_NOTNULL(SSLv23_server_method());

  auto const config_path = osutil::get_config_dir();

  auto const bio
      = CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(ffdhe4096), -1));
  auto const dh
      = CHECK_NOTNULL(PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr));

  auto const ecdh = CHECK_NOTNULL(EC_KEY_new_by_curve_name(NID_secp521r1));

  auto const certs = list_directory(config_path, Config::cert_fn_re);

  CHECK_GE(certs.size(), 1) << "no server certs found";

  for (auto const& cert : certs) {

    auto ctx = CHECK_NOTNULL(SSL_CTX_new(method));
    std::vector<Domain> cn;

    // SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    CHECK_GT(SSL_CTX_dane_enable(ctx), 0)
        << "unable to enable DANE on SSL context";

    // you'd think if it's the default, you'd not have to call this
    CHECK_EQ(SSL_CTX_set_default_verify_paths(ctx), 1);

    CHECK_GT(SSL_CTX_use_certificate_chain_file(ctx, cert.string().c_str()), 0)
        << "Can't load certificate chain file " << cert;

    auto const key = fs::path(cert).replace_extension(".key");

    if (fs::exists(key)) {

      CHECK_GT(SSL_CTX_use_PrivateKey_file(ctx, key.string().c_str(),
                                           SSL_FILETYPE_PEM),
               0)
          << "Can't load private key file " << key;

      CHECK(SSL_CTX_check_private_key(ctx))
          << "SSL_CTX_check_private_key failed for " << key;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"

    SSL_CTX_set_tmp_dh(ctx, dh);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

#pragma GCC diagnostic pop

    SSL_CTX_set_verify_depth(ctx, Config::cert_verify_depth + 1);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       verify_callback);

    // SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_callback);
    // same as:
    SSL_CTX_callback_ctrl(
        ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
        reinterpret_cast<void (*)()>(ssl_servername_callback));

    // SSL_CTX_set_tlsext_servername_arg(ctx, &cert_ctx_);
    // same as:
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0,
                 reinterpret_cast<void*>(&cert_ctx_));

    // SSL_CTX_dane_set_flags(ctx, DANE_FLAG_NO_DANE_EE_NAMECHECKS);

    //.......................................................

    auto const x509 = SSL_CTX_get0_certificate(ctx);
    if (x509) {
      X509_NAME* subj = X509_get_subject_name(x509);

      int lastpos = -1;
      for (;;) {
        lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
        if (lastpos == -1)
          break;
        auto e = X509_NAME_get_entry(subj, lastpos);
        ASN1_STRING* d = X509_NAME_ENTRY_get_data(e);
        auto str = ASN1_STRING_get0_data(d);
        LOG(INFO) << "cert found for " << str;
        cn.emplace_back(reinterpret_cast<const char*>(str));
      }

      // auto ext_stack = X509_get0_extensions(x509);
      // for (int i = 0; i < sk_X509_EXTENSION_num(ext_stack); i++) {
      //   X509_EXTENSION* ext
      //       = CHECK_NOTNULL(sk_X509_EXTENSION_value(ext_stack, i));
      //   ASN1_OBJECT* asn1_obj =
      //   CHECK_NOTNULL(X509_EXTENSION_get_object(ext)); unsigned nid =
      //   OBJ_obj2nid(asn1_obj); if (nid == NID_undef) {
      //     // no lookup found for the provided OID so nid came back as
      //     undefined. char extname[256]; OBJ_obj2txt(extname, sizeof(extname),
      //     asn1_obj, 1); LOG(INFO) << "undef extension name is " << extname;
      //   } else {
      //     // the OID translated to a NID which implies that the OID has a
      //     known
      //     // sn/ln
      //     const char* c_ext_name = CHECK_NOTNULL(OBJ_nid2ln(nid));
      //     LOG(INFO) << "extension " << c_ext_name;
      //   }
      // }

      auto subject_alt_names = static_cast<GENERAL_NAMES*>(
          X509_get_ext_d2i(x509, NID_subject_alt_name, nullptr, nullptr));

      for (int i = 0; i < sk_GENERAL_NAME_num(subject_alt_names); ++i) {

        GENERAL_NAME* gen = sk_GENERAL_NAME_value(subject_alt_names, i);

        if (gen->type == GEN_URI || gen->type == GEN_EMAIL) {
          ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;

          std::string str(
              reinterpret_cast<char const*>(ASN1_STRING_get0_data(asn1_str)),
              ASN1_STRING_length(asn1_str));

          LOG(INFO) << "email or uri ignored " << str;
        }
        else if (gen->type == GEN_DNS) {
          ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;

          std::string str(
              reinterpret_cast<char const*>(ASN1_STRING_get0_data(asn1_str)),
              ASN1_STRING_length(asn1_str));

          if (find(cn.begin(), cn.end(), str) == cn.end()) {
            LOG(INFO) << "additional name found for " << str;
            cn.emplace_back(str);
          }
          else {
            LOG(INFO) << "dup name " << str << " ignored";
          }
        }
        else if (gen->type == GEN_IPADD) {
          unsigned char* p = gen->d.ip->data;
          if (gen->d.ip->length == 4) {
            std::stringstream ip;
            ip << unsigned(p[0]) << '.' << unsigned(p[1]) << '.'
               << unsigned(p[2]) << '.' << unsigned(p[3]);

            LOG(INFO) << "alt name IP4 address " << ip.str();
          }
          else if (gen->d.ip->length == 16) {
            LOG(ERROR) << "IPv6 not implemented";
          }
          else {
            LOG(ERROR) << "unknown IP type";
          }
        }
        else {
          LOG(ERROR) << "unknown alt name type";
        }
      }

      GENERAL_NAMES_free(subject_alt_names);

      //.......................................................
    }

    cert_ctx_.emplace_back(ctx, cn);
  }

  DH_free(dh);
  BIO_free(bio);

  EC_KEY_free(ecdh);

  ssl_ = CHECK_NOTNULL(SSL_new(cert_ctx_.back().ctx));

  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  if (session_context_index < 0) {
    session_context_index
        = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  session_context context;
  SSL_set_ex_data(ssl_, session_context_index, &context);

  using namespace std::chrono;
  auto const start = system_clock::now();

  ERR_clear_error();

  int rc;
  while ((rc = SSL_accept(ssl_)) < 0) {

    time_point<system_clock> now = system_clock::now();

    CHECK(now < (start + timeout)) << "starttls timed out";

    milliseconds time_left
        = duration_cast<milliseconds>((start + timeout) - now);

    switch (SSL_get_error(ssl_, rc)) {
    case SSL_ERROR_WANT_READ:
      CHECK(POSIX::input_ready(fd_in, time_left))
          << "starttls timed out on input_ready";
      ERR_clear_error();
      continue; // try SSL_accept again

    case SSL_ERROR_WANT_WRITE:
      CHECK(POSIX::output_ready(fd_out, time_left))
          << "starttls timed out on output_ready";
      ERR_clear_error();
      continue; // try SSL_accept again

    case SSL_ERROR_SYSCALL:
      LOG(WARNING) << "errno == " << errno << ": " << strerror(errno);
      [[fallthrough]];

    default:
      ssl_error();
      return false;
    }
  }

  if (auto const peer_cert = SSL_get_peer_certificate(ssl_); peer_cert) {
    if (SSL_get_verify_result(ssl_) == X509_V_OK) {
      LOG(INFO) << "client certificate verified";
      verified_ = true;

      char const* const peername = SSL_get0_peername(ssl_);
      if (peername != nullptr) {
        // name checks were in scope and matched the peername
        LOG(INFO) << "verified peername: " << peername;
      }
      else {
        LOG(INFO) << "no verified peername";
      }

      EVP_PKEY* mspki = nullptr;
      int depth = SSL_get0_dane_authority(ssl_, nullptr, &mspki);
      if (depth >= 0) {

        uint8_t usage, selector, mtype;
        const unsigned char* certdata;
        size_t certdata_len;

        SSL_get0_dane_tlsa(ssl_, &usage, &selector, &mtype, &certdata,
                           &certdata_len);

        LOG(INFO) << "DANE TLSA " << usage << " " << selector << " " << mtype
                  << " [" << bin2hexstring(certdata, 6) << "...] "
                  << ((mspki != nullptr) ? "TA public key verified certificate"
                                         : depth ? "matched TA certificate"
                                                 : "matched EE certificate")
                  << " at depth " << depth;
      }
    }
    else {
      LOG(WARNING) << "client certificate failed to verify";
    }
  }
  else {
    LOG(INFO) << "no client certificate";
  }

  return true;
}

std::string TLS::info() const
{
  auto info{std::ostringstream{}};

  info << SSL_get_version(ssl_);
  auto const c = SSL_get_current_cipher(ssl_);
  if (c) {
    info << " version=" << SSL_CIPHER_get_version(c);
    info << " cipher=" << SSL_CIPHER_get_name(c);
    int alg_bits;
    int bits = SSL_CIPHER_get_bits(c, &alg_bits);
    info << " bits=" << bits << "/" << alg_bits;
    if (verified_) {
      info << " verified";
    }
  }

  return info.str();
}

std::streamsize TLS::io_tls_(char const* fnm,
                             std::function<int(SSL*, void*, int)> io_fnc,
                             char* s,
                             std::streamsize n,
                             std::chrono::milliseconds timeout,
                             bool& t_o)
{
  using namespace std::chrono;
  auto const start = system_clock::now();
  auto const end_time = start + timeout;

  ERR_clear_error();

  int n_ret;
  while ((n_ret = io_fnc(ssl_, static_cast<void*>(s), static_cast<int>(n)))
         < 0) {
    time_point<system_clock> now = system_clock::now();
    if (now > end_time) {
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    auto const time_left = duration_cast<milliseconds>(end_time - now);

    switch (SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_WANT_READ: {
      int fd = SSL_get_rfd(ssl_);
      CHECK_NE(-1, fd);
      read_hook_();
      if (POSIX::input_ready(fd, time_left)) {
        ERR_clear_error();
        continue; // try io_fnc again
      }
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    case SSL_ERROR_WANT_WRITE: {
      int fd = SSL_get_wfd(ssl_);
      CHECK_NE(-1, fd);
      if (POSIX::output_ready(fd, time_left)) {
        ERR_clear_error();
        continue; // try io_fnc again
      }
      LOG(WARNING) << fnm << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    case SSL_ERROR_SYSCALL:
      LOG(WARNING) << "errno == " << errno << ": " << strerror(errno);
      [[fallthrough]];

    default:
      ssl_error();
      return static_cast<std::streamsize>(-1);
    }
  }

  // The strange (and never before seen) case of 0 return.
  if (0 == n_ret) {
    switch (SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_NONE:
      LOG(INFO) << fnm << " returned SSL_ERROR_NONE";
      break;

    case SSL_ERROR_ZERO_RETURN:
      // This is a close, not at all sure this is the right thing to do.
      LOG(INFO) << fnm << " returned SSL_ERROR_ZERO_RETURN";
      break;

    default:
      LOG(INFO) << fnm << " returned zero";
      ssl_error();
    }
  }

  return static_cast<std::streamsize>(n_ret);
}

void TLS::ssl_error()
{
  unsigned long er;
  while (0 != (er = ERR_get_error()))
    LOG(WARNING) << ERR_error_string(er, nullptr);
  LOG(WARNING) << "fatal OpenSSL error";
}

#include "TLS-OpenSSL.hpp"

#include <iomanip>
#include <string>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#define FMT_STRING_ALIAS 1
#include <fmt/format.h>

#include "DNS.hpp"
#include "POSIX.hpp"
#include "osutil.hpp"

DEFINE_bool(support_all_tls_versions,
            false,
            "lift restrictions on TLS versions");

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
  ret.reserve(2 * length);

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

TLS::TLS(std::function<void(void)> read_hook)
  : read_hook_(read_hook)
{
}

TLS::~TLS()
{
  for (auto& ctx : cert_ctx_) {
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

  // auto const ssl = reinterpret_cast<SSL*>(
  //   X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));

  CHECK_GE(session_context_index, 0);

  // auto unused = reinterpret_cast<session_context*>(SSL_get_ex_data(ssl,
  // session_context_index));

  auto const depth = X509_STORE_CTX_get_error_depth(ctx);

  char buf[256];
  X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));

  if (depth > Config::cert_verify_depth) {
    preverify_ok = 0;
    err          = X509_V_ERR_CERT_CHAIN_TOO_LONG;
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
  auto cert_ctx_ptr
      = CHECK_NOTNULL(static_cast<std::vector<TLS::per_cert_ctx>*>(arg));
  auto const& cert_ctx = *cert_ctx_ptr;

  auto const servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);

  if (servername && *servername) {
    LOG(INFO) << "servername requested " << servername;
    for (auto const& ctx : cert_ctx) {
      if (auto const& c = std::find(begin(ctx.cn), end(ctx.cn), servername);
          c != end(ctx.cn)) {
        if (size(cert_ctx) > 1)
          SSL_set_SSL_CTX(s, ctx.ctx);
        return SSL_TLSEXT_ERR_OK;
      }
    }
    LOG(INFO) << "no cert found for server " << servername;
    return SSL_TLSEXT_ERR_ALERT_WARNING;
  }

  // LOG(INFO) << "no specific server name requested";
  return SSL_TLSEXT_ERR_OK;
}

bool TLS::starttls_client(fs::path                  config_path,
                          int                       fd_in,
                          int                       fd_out,
                          char const*               client_name,
                          char const*               server_name,
                          DNS::RR_collection const& tlsa_rrs,
                          bool                      enforce_dane,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  auto const method = CHECK_NOTNULL(SSLv23_client_method());

  if (client_name) {
    auto const certs = osutil::list_directory(config_path, Config::cert_fn_re);

    CHECK_GE(certs.size(), 1) << "no client cert(s) found";

    for (auto const& cert : certs) {

      auto                ctx = CHECK_NOTNULL(SSL_CTX_new(method));
      std::vector<Domain> cn;

      SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

      // // Allow any old and crufty protocol version.
      // if (FLAGS_support_all_tls_versions) {
      //   CHECK_GT(SSL_CTX_set_min_proto_version(ctx, 0), 0)
      //       << "unable to set min proto version";
      // }

      CHECK_GT(SSL_CTX_dane_enable(ctx), 0)
          << "unable to enable DANE on SSL context";

      // you'd think if it's the default, you'd not have to call this
      CHECK_EQ(SSL_CTX_set_default_verify_paths(ctx), 1);

      CHECK_GT(SSL_CTX_use_certificate_chain_file(ctx, cert.string().c_str()),
               0)
          << "Can't load certificate chain file " << cert;

      auto const key = fs::path(cert).replace_extension(Config::key_ext);

      if (fs::exists(key)) {

        CHECK_GT(SSL_CTX_use_PrivateKey_file(ctx, key.string().c_str(),
                                             SSL_FILETYPE_PEM),
                 0)
            << "Can't load private key file " << key;

        CHECK(SSL_CTX_check_private_key(ctx))
            << "SSL_CTX_check_private_key failed for " << key;
      }

      SSL_CTX_set_verify_depth(ctx, Config::cert_verify_depth + 1);
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                         verify_callback);

      //.......................................................

      auto const x509 = CHECK_NOTNULL(SSL_CTX_get0_certificate(ctx));

      X509_NAME* subj = X509_get_subject_name(x509);

      int lastpos = -1;
      for (;;) {
        lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
        if (lastpos == -1)
          break;
        auto         e   = X509_NAME_get_entry(subj, lastpos);
        ASN1_STRING* d   = X509_NAME_ENTRY_get_data(e);
        auto         str = ASN1_STRING_get0_data(d);
        // LOG(INFO) << "client cert found for " << str;
        cn.emplace_back(reinterpret_cast<const char*>(str));
      }

      auto subject_alt_names = static_cast<GENERAL_NAMES*>(
          X509_get_ext_d2i(x509, NID_subject_alt_name, nullptr, nullptr));

      for (int i = 0; i < sk_GENERAL_NAME_num(subject_alt_names); ++i) {

        GENERAL_NAME* gen = sk_GENERAL_NAME_value(subject_alt_names, i);

        if (gen->type == GEN_URI || gen->type == GEN_EMAIL) {
          ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;

          std::string const str(
              reinterpret_cast<char const*>(ASN1_STRING_get0_data(asn1_str)),
              ASN1_STRING_length(asn1_str));

          LOG(INFO) << "email or uri alt name " << str;
        }
        else if (gen->type == GEN_DNS) {
          ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;

          std::string str(
              reinterpret_cast<char const*>(ASN1_STRING_get0_data(asn1_str)),
              ASN1_STRING_length(asn1_str));

          if (find(begin(cn), end(cn), str) == end(cn)) {
            // LOG(INFO) << "additional name found " << str;
            cn.emplace_back(str);
          }
          else {
            // LOG(INFO) << "duplicate name " << str << " ignored";
          }
        }
        else if (gen->type == GEN_IPADD) {
          unsigned char* p = gen->d.ip->data;
          if (gen->d.ip->length == 4) {
            auto const ip = fmt::format(FMT_STRING("{:d}.{:d}.{:d}.{:d}"), p[0],
                                        p[1], p[2], p[3]);
            LOG(INFO) << "alt name IP4 address " << ip;
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

      if (std::find(begin(cn), end(cn), client_name) != end(cn)) {
        // LOG(INFO) << "**** using cert for " << client_name;
        cert_ctx_.emplace_back(ctx, cn);
      }
    }
  }

  if (cert_ctx_.empty()) {
    LOG(INFO) << "no cert found for client " << client_name;

    auto ctx = CHECK_NOTNULL(SSL_CTX_new(method));
    CHECK_GT(SSL_CTX_dane_enable(ctx), 0)
        << "unable to enable DANE on SSL context";

    // you'd think if it's the default, you'd not have to call this
    CHECK_EQ(SSL_CTX_set_default_verify_paths(ctx), 1);

    SSL_CTX_set_verify_depth(ctx, Config::cert_verify_depth + 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       verify_callback);

    LOG(INFO) << "**** using no client cert";

    std::vector<Domain> cn;
    cert_ctx_.emplace_back(ctx, cn);
  }

  ssl_ = CHECK_NOTNULL(SSL_new(cert_ctx_.back().ctx));

  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  // LOG(INFO) << "tlsa_rrs.size() == " << tlsa_rrs.size();

  if (tlsa_rrs.size()) {
    CHECK_GE(SSL_dane_enable(ssl_, server_name), 0)
        << "SSL_dane_enable() failed";
    LOG(INFO) << "SSL_dane_enable(ssl_, " << server_name << ")";
  }
  else {
    CHECK_EQ(SSL_set1_host(ssl_, server_name), 1);

    // SSL_set_tlsext_host_name(ssl_, server_name);
    // same as:
    CHECK_EQ(SSL_ctrl(ssl_, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                      TLSEXT_NAMETYPE_host_name,
                      const_cast<char*>(server_name)),
             1);
    // LOG(INFO) << "SSL_set1_host and SSL_set_tlsext_host_name " <<
    // server_name;
  }

  // No partial label wildcards
  SSL_set_hostflags(ssl_, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

  auto usable_TLSA_records = 0;

  for (auto const& tlsa_rr : tlsa_rrs) {
    if (std::holds_alternative<DNS::RR_TLSA>(tlsa_rr)) {
      auto const rp   = std::get<DNS::RR_TLSA>(tlsa_rr);
      auto       data = rp.assoc_data();
      auto       rc   = SSL_dane_tlsa_add(ssl_, rp.cert_usage(), rp.selector(),
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

  // CHECK_EQ(SSL_set_tlsext_host_name(ssl_, server_name), 1);
  // same as:
  // CHECK_EQ(SSL_ctrl(ssl_, SSL_CTRL_SET_TLSEXT_HOSTNAME,
  //                   TLSEXT_NAMETYPE_host_name,
  //                   const_cast<char*>(server_name)),
  //          1);
  // LOG(INFO) << "SSL_set_tlsext_host_name == " << server_name;

  if (session_context_index < 0) {
    session_context_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  session_context context;
  SSL_set_ex_data(ssl_, session_context_index, &context);

  auto const start = std::chrono::system_clock::now();

  ERR_clear_error();

  int rc;
  while ((rc = SSL_connect(ssl_)) < 0) {

    auto const now = std::chrono::system_clock::now();

    CHECK(now < (start + timeout)) << "starttls timed out";

    auto time_left = std::chrono::duration_cast<std::chrono::milliseconds>(
        (start + timeout) - now);

    int n_get_err;
    switch (n_get_err = SSL_get_error(ssl_, rc)) {
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

    default: ssl_error(n_get_err);
    }
  }

  if (SSL_get_verify_result(ssl_) == X509_V_OK) {
    LOG(INFO) << "server certificate verified";
    verified_ = true;

    char const* const peername = SSL_get0_peername(ssl_);
    if (peername != nullptr) {
      // Name checks were in scope and matched the peername
      verified_peername_ = peername;
      LOG(INFO) << "verified peername: " << peername;
    }
    else {
      LOG(INFO) << "no verified peername";
    }

    EVP_PKEY* mspki = nullptr;
    int       depth = SSL_get0_dane_authority(ssl_, nullptr, &mspki);
    if (depth >= 0) {

      uint8_t              usage, selector, mtype;
      const unsigned char* certdata;
      size_t               certdata_len;

      SSL_get0_dane_tlsa(ssl_, &usage, &selector, &mtype, &certdata,
                         &certdata_len);

      LOG(INFO) << "DANE TLSA " << unsigned(usage) << " " << unsigned(selector)
                << " " << unsigned(mtype) << " [" << bin2hexstring(certdata, 6)
                << "...] "
                << ((mspki != nullptr) ? "TA public key verified certificate"
                    : depth            ? "matched TA certificate"
                                       : "matched EE certificate")
                << " at depth " << depth;
    }
    else if (usable_TLSA_records && enforce_dane) {
      LOG(WARNING) << "enforcing DANE; failing starttls";
      return false;
    }
  }
  else {
    LOG(WARNING) << "server certificate failed to verify";
  }

  return true;
}

bool TLS::starttls_server(fs::path                  config_path,
                          int                       fd_in,
                          int                       fd_out,
                          std::chrono::milliseconds timeout)
{
  SSL_load_error_strings();
  SSL_library_init();

  CHECK(RAND_status()); // Be sure the PRNG has been seeded with enough data.

  auto const method = CHECK_NOTNULL(SSLv23_server_method());

  auto const bio =
      CHECK_NOTNULL(BIO_new_mem_buf(const_cast<char*>(ffdhe4096), -1));

  auto const certs = osutil::list_directory(config_path, Config::cert_fn_re);

  CHECK_GE(certs.size(), 1) << "no server cert(s) found";

  for (auto const& cert : certs) {

    auto                ctx = CHECK_NOTNULL(SSL_CTX_new(method));
    std::vector<Domain> names;

    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_clear_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

    // Allow any old and crufty protocol version.
    // if (FLAGS_support_all_tls_versions) {
    //   CHECK_GT(SSL_CTX_set_min_proto_version(ctx, 0), 0)
    //       << "unable to set min proto version";
    // }

    CHECK_GT(SSL_CTX_dane_enable(ctx), 0)
        << "unable to enable DANE on SSL context";

    // you'd think if it's the default, you'd not have to call this
    CHECK_EQ(SSL_CTX_set_default_verify_paths(ctx), 1);

    CHECK_GT(SSL_CTX_use_certificate_chain_file(ctx, cert.string().c_str()), 0)
        << "Can't load certificate chain file " << cert;

    auto const key = fs::path(cert).replace_extension(Config::key_ext);

    if (fs::exists(key)) {

      CHECK_GT(SSL_CTX_use_PrivateKey_file(ctx, key.string().c_str(),
                                           SSL_FILETYPE_PEM),
               0)
          << "Can't load private key file " << key;

      CHECK(SSL_CTX_check_private_key(ctx))
          << "SSL_CTX_check_private_key failed for " << key;
    }

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

    auto const x509 = CHECK_NOTNULL(SSL_CTX_get0_certificate(ctx));

    X509_NAME* subj = X509_get_subject_name(x509);

    int lastpos = -1;
    for (;;) {
      lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
      if (lastpos == -1)
        break;
      auto         e   = X509_NAME_get_entry(subj, lastpos);
      ASN1_STRING* d   = X509_NAME_ENTRY_get_data(e);
      auto         str = ASN1_STRING_get0_data(d);
      // LOG(INFO) << "server cert found for " << str;
      names.emplace_back(reinterpret_cast<const char*>(str));
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

        LOG(INFO) << "email or uri alt name " << str;
      }
      else if (gen->type == GEN_DNS) {
        ASN1_IA5STRING* asn1_str = gen->d.uniformResourceIdentifier;

        std::string str(
            reinterpret_cast<char const*>(ASN1_STRING_get0_data(asn1_str)),
            ASN1_STRING_length(asn1_str));

        if (find(begin(names), end(names), str) == end(names)) {
          // LOG(INFO) << "additional name found " << str;
          names.emplace_back(str);
        }
        else {
          // LOG(INFO) << "duplicate name " << str << " ignored";
        }
      }
      else if (gen->type == GEN_IPADD) {
        unsigned char* p = gen->d.ip->data;
        if (gen->d.ip->length == 4) {
          auto const ip = fmt::format(FMT_STRING("{:d}.{:d}.{:d}.{:d}"), p[0],
                                      p[1], p[2], p[3]);
          LOG(INFO) << "alt name IP4 address " << ip;
          names.emplace_back(ip);
        }
        else if (gen->d.ip->length == 16) {
          // FIXME!
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

    cert_ctx_.emplace_back(ctx, names);
  }

  BIO_free(bio);

  ssl_ = CHECK_NOTNULL(SSL_new(cert_ctx_.back().ctx));

  SSL_set_rfd(ssl_, fd_in);
  SSL_set_wfd(ssl_, fd_out);

  if (session_context_index < 0) {
    session_context_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }
  session_context context;
  SSL_set_ex_data(ssl_, session_context_index, &context);

  auto const start = std::chrono::system_clock::now();

  ERR_clear_error();

  int rc;
  while ((rc = SSL_accept(ssl_)) < 0) {

    auto const now = std::chrono::system_clock::now();

    CHECK(now < (start + timeout)) << "starttls timed out";

    auto const time_left =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            (start + timeout) - now);

    int n_get_err;
    switch (n_get_err = SSL_get_error(ssl_, rc)) {
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

    default: ssl_error(n_get_err);
    }
  }

  if (auto const peer_cert = SSL_get_peer_certificate(ssl_); peer_cert) {
    if (SSL_get_verify_result(ssl_) == X509_V_OK) {
      LOG(INFO) << "client certificate verified";
      verified_ = true;

      char const* const peername = SSL_get0_peername(ssl_);
      if (peername != nullptr) {
        // name checks were in scope and matched the peername
        verified_peername_ = peername;
        LOG(INFO) << "verified peername: " << peername;
      }
      else {
        LOG(INFO) << "no verified peername";
      }

      EVP_PKEY* mspki = nullptr;
      int       depth = SSL_get0_dane_authority(ssl_, nullptr, &mspki);
      if (depth >= 0) {

        uint8_t              usage, selector, mtype;
        const unsigned char* certdata;
        size_t               certdata_len;

        SSL_get0_dane_tlsa(ssl_, &usage, &selector, &mtype, &certdata,
                           &certdata_len);

        LOG(INFO) << "DANE TLSA " << usage << " " << selector << " " << mtype
                  << " [" << bin2hexstring(certdata, 6) << "...] "
                  << ((mspki != nullptr) ? "TA public key verified certificate"
                      : depth            ? "matched TA certificate"
                                         : "matched EE certificate")
                  << " at depth " << depth;
      }
    }
    else {
      LOG(WARNING) << "client certificate failed to verify";
    }
  }
  else {
    // LOG(INFO) << "no client certificate offerd to us";
  }

  return true;
}

std::string TLS::info() const
{
  // same as SSL_CIPHER_get_version() below
  // info << SSL_get_version(ssl_);

  auto const c = SSL_get_current_cipher(ssl_);
  if (c) {
    int alg_bits;
    int bits = SSL_CIPHER_get_bits(c, &alg_bits);
    return fmt::format("version={} cipher={} bits={}/{}{}",
                       SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c), bits,
                       alg_bits, (verified_ ? " verified" : ""));
  }

  return "";
}

std::streamsize TLS::io_tls_(char const*                          fn,
                             std::function<int(SSL*, void*, int)> io_fnc,
                             char*                                s,
                             std::streamsize                      n,
                             std::chrono::milliseconds            timeout,
                             bool&                                t_o)
{
  auto const start    = std::chrono::system_clock::now();
  auto const end_time = start + timeout;

  ERR_clear_error();

  int n_ret;
  while ((n_ret = io_fnc(ssl_, static_cast<void*>(s), static_cast<int>(n)))
         < 0) {
    auto const now = std::chrono::system_clock::now();
    if (now > end_time) {
      LOG(WARNING) << fn << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    auto const time_left
        = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - now);

    int n_get_err;
    switch (n_get_err = SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_WANT_READ: {
      int fd = SSL_get_rfd(ssl_);
      CHECK_NE(-1, fd);
      read_hook_();
      if (POSIX::input_ready(fd, time_left)) {
        ERR_clear_error();
        continue; // try io_fnc again
      }
      LOG(WARNING) << fn << " timed out";
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
      LOG(WARNING) << fn << " timed out";
      t_o = true;
      return static_cast<std::streamsize>(-1);
    }

    case SSL_ERROR_SYSCALL:
      LOG(WARNING) << "errno == " << errno << ": " << strerror(errno);
      [[fallthrough]];

    default: ssl_error(n_get_err);
    }
  }

  // The strange (and never before seen) case of 0 return.
  if (0 == n_ret) {
    int n_get_err;
    switch (n_get_err = SSL_get_error(ssl_, n_ret)) {
    case SSL_ERROR_NONE: LOG(INFO) << fn << " returned SSL_ERROR_NONE"; break;

    case SSL_ERROR_ZERO_RETURN:
      // This is a close, not at all sure this is the right thing to do.
      LOG(INFO) << fn << " returned SSL_ERROR_ZERO_RETURN";
      break;

    default: LOG(INFO) << fn << " returned zero"; ssl_error(n_get_err);
    }
  }

  return static_cast<std::streamsize>(n_ret);
}

void TLS::ssl_error(int n_get_err)
{
  LOG(WARNING) << "n_get_err == " << n_get_err;
  switch (n_get_err) {
  case SSL_ERROR_NONE: LOG(WARNING) << "SSL_ERROR_NONE"; break;
  case SSL_ERROR_ZERO_RETURN: LOG(WARNING) << "SSL_ERROR_ZERO_RETURN"; break;
  case SSL_ERROR_WANT_READ: LOG(WARNING) << "SSL_ERROR_WANT_READ"; break;
  case SSL_ERROR_WANT_WRITE: LOG(WARNING) << "SSL_ERROR_WANT_WRITE"; break;
  case SSL_ERROR_WANT_CONNECT: LOG(WARNING) << "SSL_ERROR_WANT_CONNECT"; break;
  case SSL_ERROR_WANT_ACCEPT: LOG(WARNING) << "SSL_ERROR_WANT_ACCEPT"; break;
  case SSL_ERROR_WANT_X509_LOOKUP:
    LOG(WARNING) << "SSL_ERROR_WANT_X509_LOOKUP";
    break;
  case SSL_ERROR_SSL: LOG(WARNING) << "SSL_ERROR_SSL"; break;
  }
  unsigned long er;
  while (0 != (er = ERR_get_error()))
    LOG(WARNING) << ERR_error_string(er, nullptr);
  LOG(WARNING) << "fatal OpenSSL error";
  exit(1);
}

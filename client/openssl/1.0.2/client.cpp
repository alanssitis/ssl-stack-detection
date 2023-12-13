// Parts of the source code were obtained from
// https://github.com/ctz/openssl-bench/tree/7bc3277b062c598463d60e6d821198ec5c7a4763
// Cleaned it up and simplified so it relies on external server
#include <array>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static bool chkerr(int err) {
  if (err == SSL_ERROR_SYSCALL) {
    ERR_print_errors_fp(stdout);
    exit(1);
    return true;
  }
  return err == 0;
}

class Context {
  ssl_ctx_st *m_ctx;

public:
  Context(ssl_ctx_st *ctx) : m_ctx(ctx) {
    SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_options(m_ctx, SSL_OP_NO_COMPRESSION);
  }

  ~Context() { SSL_CTX_free(m_ctx); }

  ssl_st *open() { return SSL_new(m_ctx); }

  void load_client_creds(const char *path) {
    int err;
    err = SSL_CTX_load_verify_locations(m_ctx, path, NULL);
    assert(err == 1);
  }

  /*
  void set_version(int minversion, int maxversion) {
    SSL_CTX_set_ssl_version(m_ctx, minversion);
  }
  */

  void set_ciphers(const std::string &ciphers) {
    // set_version(TLS1_VERSION, TLS1_VERSION);
    if (!SSL_CTX_set_cipher_list(m_ctx, ciphers.c_str())) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }

  static Context client() {
    return Context(SSL_CTX_new(TLSv1_2_client_method()));
  }
};

class Conn {
  ssl_st *m_ssl;
  std::string address = "127.0.0.1:443";

  Conn(const Conn &) = delete;
  Conn &operator=(const Conn &) = delete;

public:
  Conn(ssl_st *ssl) : m_ssl(ssl) {
    auto bio = BIO_new_connect(address.data());
    SSL_set_bio(m_ssl, bio, bio);
  }

  ~Conn() { SSL_free(m_ssl); }

  void set_sni(const char *hostname) {
    int err;
    err = SSL_set_tlsext_host_name(m_ssl, hostname);
    assert(err == 1);
  }

  void set_client() { SSL_set_connect_state(m_ssl); }

  bool connect() { return chkerr(SSL_get_error(m_ssl, SSL_connect(m_ssl))); }

  bool accept() { return chkerr(SSL_get_error(m_ssl, SSL_accept(m_ssl))); }

  void dump_cipher() {
    printf("negotiated %s with %s\n", SSL_get_cipher_version(m_ssl),
           SSL_get_cipher(m_ssl));
  }

  void write(const uint8_t *buf, size_t n) {
    chkerr(SSL_get_error(m_ssl, SSL_write(m_ssl, buf, n)));
  }

  void read(uint8_t *buf, size_t n) {
    while (n) {
      int rd = SSL_read(m_ssl, buf, n);

      assert(rd >= 0);
      buf += rd;
      n -= rd;
    }
  }

  int handshake() { return SSL_get_error(m_ssl, SSL_do_handshake(m_ssl)); }
};

static int get_points_number() {
  const char *points = getenv("POINTS");
  if (points) {
    return atof(points);
  }
  return 1;
}

static double test_handshake(Context &client_ctx) {
  Conn client(client_ctx.open());

  client.set_client();
  client.set_sni("localhost");

  auto start = std::chrono::high_resolution_clock::now();
  auto ret = client.handshake();
  auto end = std::chrono::high_resolution_clock::now();

  if (ret != SSL_ERROR_NONE) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return std::chrono::duration<double>(end - start).count();
}

static int usage() {
  std::cout << "usage: client <ip> <cert>" << std::endl;
  return 1;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    return usage();
  }
  SSL_load_error_strings();
  SSL_library_init();

  std::array<std::string, 6> ciphersuites{
      // Valid TLS v1.2 cipher suites
      "AES128-SHA256",
      "AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "ECDHE-RSA-AES128-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
  };

  std::cout << "idx";
  for (auto &cs : ciphersuites) {
    std::cout << "," << cs;
  }
  std::cout << std::endl;

  for (auto i = 0; i < get_points_number(); i++) {
    std::cout << i;
    for (auto &cs : ciphersuites) {
      Context client_ctx = Context::client();
      client_ctx.load_client_creds(argv[2]);
      client_ctx.set_ciphers(cs);
      std::cout << "," << test_handshake(client_ctx);
    }
    std::cout << std::endl;
  }

  return 0;
}

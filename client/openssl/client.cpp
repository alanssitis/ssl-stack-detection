#include <cerrno>
#include <cstring>

#include <iostream>
#include <openssl/prov_ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <unistd.h>

// Valid TLS v1.2 cipher suites
// TLS_RSA_WITH_NULL_SHA256
// TLS_RSA_WITH_AES_128_CBC_SHA256
// TLS_RSA_WITH_AES_256_CBC_SHA256
// TLS_RSA_WITH_AES_128_GCM_SHA256
// TLS_RSA_WITH_AES_256_GCM_SHA384
// TLS_DH_RSA_WITH_AES_128_CBC_SHA256
// TLS_DH_RSA_WITH_AES_256_CBC_SHA256
// TLS_DH_RSA_WITH_AES_128_GCM_SHA256
// TLS_DH_RSA_WITH_AES_256_GCM_SHA384
// TLS_DH_DSS_WITH_AES_128_CBC_SHA256
// TLS_DH_DSS_WITH_AES_256_CBC_SHA256
// TLS_DH_DSS_WITH_AES_128_GCM_SHA256
// TLS_DH_DSS_WITH_AES_256_GCM_SHA384
// TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
// TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
// TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
// TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
// TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
// TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
// TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
// TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
// TLS_DH_anon_WITH_AES_128_CBC_SHA256
// TLS_DH_anon_WITH_AES_256_CBC_SHA256
// TLS_DH_anon_WITH_AES_128_GCM_SHA256
// TLS_DH_anon_WITH_AES_256_GCM_SHA384
// RSA_WITH_AES_128_CCM
// RSA_WITH_AES_256_CCM
// DHE_RSA_WITH_AES_128_CCM
// DHE_RSA_WITH_AES_256_CCM
// RSA_WITH_AES_128_CCM_8
// RSA_WITH_AES_256_CCM_8
// DHE_RSA_WITH_AES_128_CCM_8
// DHE_RSA_WITH_AES_256_CCM_8
// ECDHE_ECDSA_WITH_AES_128_CCM
// ECDHE_ECDSA_WITH_AES_256_CCM
// ECDHE_ECDSA_WITH_AES_128_CCM_8
// ECDHE_ECDSA_WITH_AES_256_CCM_8

// Valid TLS v1.3 cipher suites
// TLS_AES_128_GCM_SHA256
// TLS_AES_256_GCM_SHA384
// TLS_CHACHA20_POLY1305_SHA256
// TLS_AES_128_CCM_SHA256
// TLS_AES_128_CCM_8_SHA256

int OpenConnection(const char *hostname, const char *port) {
  struct addrinfo hints{0}, *addrs;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  const int status = getaddrinfo(hostname, port, &hints, &addrs);
  if (status != 0) {
    std::cerr << hostname << ": " << gai_strerror(status) << std::endl;
    exit(EXIT_FAILURE);
  }

  int sfd = -1;
  for (struct addrinfo *addr = addrs; addr != nullptr; addr = addr->ai_next) {
    sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
    if (sfd == -1) {
      std::cerr << "socket() failed: " << strerror(errno) << std::endl;
      continue;
    }

    if (connect(sfd, addr->ai_addr, addr->ai_addrlen) == -1) {
      std::cerr << "socket() failed: " << strerror(errno) << std::endl;
    }
    break;
  }

  freeaddrinfo(addrs);

  if (sfd == -1) {
    std::cerr << "Could not attach to a socket" << std::endl;
    exit(EXIT_FAILURE);
  }
  return sfd;
}

int main() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == nullptr) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // TLS 1.2
  /*
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list(ctx, "RSA_WITH_AES_128_CCM");
  */

  // TLS 1.3
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");

  SSL_CTX_load_verify_locations(ctx, "server.crt", "../../go_server/");

  SSL *ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    std::cerr << "SSL_new() failed" << std::endl;
    exit(EXIT_FAILURE);
  }
  SSL_set_connect_state(ssl);

  const int sfd = OpenConnection("127.0.0.1", "443");
  SSL_set_fd(ssl, sfd);

  const int status = SSL_do_handshake(ssl);
  if (status != 1) {
    SSL_get_error(ssl, status);
    ERR_print_errors_fp(stderr);
    std::cerr << "SSL_connect failed with SSL_get_error code " << status << std::endl;
    exit(EXIT_FAILURE);
  }

  std::cout << "Current ciphersuite: " << SSL_get_cipher(ssl) << std::endl;
  SSL_free(ssl);
  close(sfd);
  SSL_CTX_free(ctx);
  return 0;
}

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

// void makeGetRequest(WOLFSSL* ssl) {
//     // Send the HTTP request
//     const char* http_request = "GET / HTTP/1.1\r\n"
//                                "Host: 172.20.0.1:4443\r\n"
//                                "Connection: close\r\n\r\n";

//     int ret = wolfSSL_write(ssl, http_request, strlen(http_request));
//     if (ret < 0) {
//         fprintf(stderr, "Error sending HTTP request\n");
//     }

//     // Receive and print the HTTP response
//     char buffer[4096];
//     memset(buffer, 0, sizeof(buffer));
//     ret = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
//     if (ret < 0) {
//         fprintf(stderr, "Error receiving HTTP response\n");
//     } else {
//         printf("HTTP Response:\n%s\n", buffer);
//     }
// }

double measureHandshakeTime(const char* host, int port, const char* cipher_suite) {
    clock_t start, end;
    double elapsed;
    //     WOLFSSL_CTX* ctx;
    // WOLFSSL* ssl;
    int ret;
    // int sockfd;  // File descriptor for the socket

    // Initialize wolfSSL
    wolfSSL_Init();

    start = clock();

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error creating socket\n");
        return -1;
    }

    // Specify the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address\n");
        close(sockfd);
        return -1;
    }
    // Create a wolfSSL context
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating wolfSSL context\n");
        close(sockfd);
        return -1;
    }

    // Set the desired cipher suite
    if (wolfSSL_CTX_set_cipher_list(ctx, cipher_suite) != SSL_SUCCESS) {
        fprintf(stderr, "Error setting cipher suite\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Load CA certificates
    if (wolfSSL_CTX_load_verify_locations(ctx, "./server.crt", 0) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading CA certificates\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error connecting to the server\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Create a wolfSSL object
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating wolfSSL object\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Set the file descriptor for the SSL connection
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "Error setting file descriptor\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Initiate the SSL/TLS handshake
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "Error establishing SSL Connection\n");
        wolfSSL_free(ssl);
        return -1.0;
    }

    // Cleanup for this cipher suite
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    // Cleanup
    close(sockfd);

    wolfSSL_Cleanup();
    end = clock();
    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    return elapsed;
}

int main(void) {
    // Specify the host and port to connect to
    const char* host = "172.20.0.1";
    int port = 4443;

    // Loop over various cipher suites
    const char* cipher_suites[] = {
        // "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        // "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        // "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        // "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        // "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    };

    // const char* cipher_suites[] = {
    //     // "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    //     // "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    //     // "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    //     // "TLS_RSA_WITH_AES_256_CBC_SHA",
    //     // "TLS_RSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_RSA_WITH_NULL_SHA",
    //     // "TLS_PSK_WITH_AES_256_CBC_SHA",
    //     // "TLS_PSK_WITH_AES_128_CBC_SHA256",
    //     // "TLS_PSK_WITH_AES_256_CBC_SHA384",
    //     // "TLS_PSK_WITH_AES_128_CBC_SHA",
    //     // "TLS_PSK_WITH_NULL_SHA256",
    //     // "TLS_PSK_WITH_NULL_SHA384",
    //     // "TLS_PSK_WITH_NULL_SHA",
    //     // "SSL_RSA_WITH_RC4_128_SHA",
    //     // "SSL_RSA_WITH_RC4_128_MD5",
    //     // "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    //     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    //     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    //     // "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    //     // "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    //     // "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    //     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    //     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    //     // "TLS_ECDHE_PSK_WITH_NULL_SHA256",
    //     // "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    //     // "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    //     // "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    //     // "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    //     // "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    //     // "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    //     // "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    //     // "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    //     // "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    //     // "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    //     // "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    //     // "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    //     // "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    //     // "TLS_RSA_WITH_AES_128_CBC_B2B256",
    //     // "TLS_RSA_WITH_AES_256_CBC_B2B256",
    //     // "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    //     // "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    //     // "TLS_RSA_WITH_AES_256_CBC_SHA256",
    //     // "TLS_RSA_WITH_AES_128_CBC_SHA256",
    //     // "TLS_RSA_WITH_NULL_SHA256",
    //     // "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    //     // "TLS_DHE_PSK_WITH_NULL_SHA256",
    //     // "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    //     // "TLS_DHE_PSK_WITH_NULL_SHA384",
    //     // "TLS_RSA_WITH_AES_128_GCM_SHA256",
    //     // "TLS_RSA_WITH_AES_256_GCM_SHA384",
    //     // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    //     // "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    //     // "TLS_PSK_WITH_AES_128_GCM_SHA256",
    //     // "TLS_PSK_WITH_AES_256_GCM_SHA384",
    //     // "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    //     // "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    //     // "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    //     // "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    //     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    //     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    //     // "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    //     // "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    //     // "TLS_RSA_WITH_AES_128_CCM_8",
    //     // "TLS_RSA_WITH_AES_256_CCM_8",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    //     // "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    //     // "TLS_PSK_WITH_AES_128_CCM",
    //     // "TLS_PSK_WITH_AES_256_CCM",
    //     // "TLS_PSK_WITH_AES_128_CCM_8",
    //     // "TLS_PSK_WITH_AES_256_CCM_8",
    //     // "TLS_DHE_PSK_WITH_AES_128_CCM",
    //     // "TLS_DHE_PSK_WITH_AES_256_CCM",
    //     // "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    //     // "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    //     // "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    //     // "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    //     // "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    //     // "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    //     // "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    //     // "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    //     // "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    //     // "TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256",
    //     // "TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256",
    //     // "TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256",
    //     // "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
    // };

    for (int i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); ++i) {
        

        // Measure handshake time for 5 iterations
        double total_elapsed = 0.0;
        for (int j = 0; j < 5; ++j) {
            double elapsed = measureHandshakeTime(host, port, cipher_suites[i]);
            if (elapsed < 0.0) {
                // Handle error
                break;
            }

            printf("Handshake time for cipher suite %s, iteration %d: %f seconds\n", cipher_suites[i], j + 1, elapsed);
            total_elapsed += elapsed;

            // Make GET request after successful handshake
            // makeGetRequest(ssl);
        }

        // Calculate and print average handshake time
        double average_elapsed = total_elapsed / 5.0;
        printf("Average handshake time for cipher suite %s: %f seconds\n", cipher_suites[i], average_elapsed);
    }

    return 0;
}


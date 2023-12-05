// client.c

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    int sockfd;  // File descriptor for the socket

    // Specify the host and port to connect to
    const char* host = "172.20.0.1";
    int port = 4443;

    // Initialize wolfSSL
    wolfSSL_Init();

    // Create a wolfSSL context
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating wolfSSL context\n");
        return -1;
    }
     // Set the desired cipher suite (replace with your preferred cipher suite)
    if (wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256") != SSL_SUCCESS) {
        fprintf(stderr, "Error setting cipher suite\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Load CA certificates (replace with the path to your CA certificate)
    if (wolfSSL_CTX_load_verify_locations(ctx, "./server.crt", 0) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading CA certificates\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }
    // Create a wolfSSL object
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating wolfSSL object\n");
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error creating socket\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Specify the server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address\n");
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error connecting to the server\n");
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Set the file descriptor for the SSL connection
    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "Error setting file descriptor\n");
        close(sockfd);  // Close the socket
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    // Initiate the SSL/TLS handshake
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
	fprintf(stderr, "Error establishing SSL Connection\n");
        //fprintf(stderr, "Error establishing SSL connection: %s\n", wolfSSL_ERR_error_string(ret));
        close(sockfd);  // Close the socket
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    printf("SSL Connection established successfully\n");

    // Use the SSL connection here

	const char* http_request = "GET / HTTP/1.1\r\n"
                           "Host: 172.20.0.1:4443\r\n"  // Update this with your server's IP and port
                           "Connection: close\r\n\r\n";

	// Send the HTTP request
	ret = wolfSSL_write(ssl, http_request, strlen(http_request));
	if (ret < 0) {
    		fprintf(stderr, "Error sending HTTP request\n");
    		close(sockfd);  // Close the socket
    		wolfSSL_free(ssl);
    		wolfSSL_CTX_free(ctx);
    		return -1;
	}

	// Receive and print the HTTP response
	char buffer[4096];
	memset(buffer, 0, sizeof(buffer));
	ret = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
	if (ret < 0) {
    		fprintf(stderr, "Error receiving HTTP response\n");
    		close(sockfd);  // Close the socket
    		wolfSSL_free(ssl);
    		wolfSSL_CTX_free(ctx);
    		return -1;
	}

	printf("HTTP Response:\n%s\n", buffer);

    // Cleanup
    close(sockfd);  // Close the socket
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    wolfSSL_Cleanup();

    return 0;
}

/*
 Encrypted Communication using sockets and OpenSSL.
 Client-Server message application with encryption/decryption, authentication.
 This demonstrates the use of sockets and OpenSSL AES encryption, authentication.
 See: https://wiki.openssl.org/index.php/EVP
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT            8080
#define BUFFER_SIZE     1024
#define AES_KEY_SIZE    256
#define AES_BLOCK_SIZE  16

// Initializes OpenSSL
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleans OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Creates OpenSSL context.
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Reads generated authentiaction files to configure the OpenSSl context.
void configure_context(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
	// Load certificate file.
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

	// Load key file.
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

	// Check private key.
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key.\n");
        exit(EXIT_FAILURE);
    }
}

// Handles encryption via OpenSSL EVP
// Encrypts plaintext using AES-256-CBC.
// Takes plaintext, key, IV (initialization vector); writes encrypted message to ciphertext.
// Steps:
// 1. Create encryption context (EVP_CIPHER_CTX).
// 2. Initialize encryption using EVP_EncryptInit_ex with AES-256-CBC.
// 3. Use EVP_EncryptUpdate and EVP_EncryptFinal_ex to encypt the message.
// 4. Free encryption context.
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    int len, ciphertext_len;

	// Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Initialize encryption to use AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    // Encrypt plaintext message
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    // Free encryption context
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Note: decrypt() removed, server uses built in function.

// Starts a server, accepts a connection, and loops to echo clients messages.
// Steps:
// 1. Creating socket, set settings
// 2. Bind socket
// 3. Listen for connections on socket
// 4. Accept a connection
// 5. Try to perform OpenSSL handshake (authentication)
// 5. Loop to recieve message, decrypt, and respond (echo)
// 6. Clean up after done with client
void server() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Initialize OpenSSL
    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx, "server.crt", "server.key");

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

	// Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

	// Listen for connection
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server listening on port %d...\n", PORT);

	// Accept connection
    int client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (client_fd < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    // Try SSL handshake
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
    	// Conenction successful
        printf("SSL connection established.\n");

        char buffer[BUFFER_SIZE] = {0};
        int bytes;

        while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes] = '\0';
            printf("Client: \"%s\"\n", buffer);
            SSL_write(ssl, buffer, strlen(buffer)); // Echo message
        }
    }

	// Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);

    SSL_CTX_free(ctx);
    cleanup_openssl();
}

// Starts a client, tries to connect to server, recieves input, sends to server.
// Steps:
// 1. Initialize OpenSSL
// 2. Create socket, set settings
// 3. Attempt to connect to server
// 4. Attempt to authenticate server
// 5. Loop, get input, encrypt, send to server
// 5. After done, clean up
void client(const char *server_ip) {
    int sock;
    struct sockaddr_in serv_addr;
    unsigned char key[AES_KEY_SIZE / 8] = "01234567890123456789012345678901"; // 32 bytes key
    unsigned char iv[AES_BLOCK_SIZE] =    "0123456789012345";                 // 16 bytes IV
	 unsigned char encrypted[BUFFER_SIZE]; // Encrypted message

    // Initialize OpenSSL
    initialize_openssl();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL *ssl = SSL_new(ctx);

	// Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

	// Attempt to connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

	// Attempt to authenticate server
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else { // Authentication success!
        printf("SSL connection established.\n");

        char buffer[BUFFER_SIZE] = {0};
        while (1) {
            // Get message from user
        	printf("> ");
        	fgets(buffer, BUFFER_SIZE, stdin);
        	buffer[strcspn(buffer, "\n")] = '\0';


			// Encrypt message
        	int encrypted_len = encrypt((unsigned char *)buffer, strlen(buffer), key, iv, encrypted);
        	if (encrypted_len < 0) {
	            perror("Encryption failed");
    	        break;
	        }

			// Print encrypted message
        	printf("Encrypted message: 0x");
        	for (int i = 0; i < encrypted_len; i++) {
	            printf("%02x", encrypted[i]);
        	}
        	printf("\n");

			// Send message to server
            SSL_write(ssl, buffer, strlen(buffer)); // Automatically encrypts message

            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("Server: %s\n", buffer);
            } else {
                break;
            }
        }
    }

	// Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    SSL_CTX_free(ctx);
    cleanup_openssl();
}

// Starts a client or a server, depending on CLI args
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server|client> [server_ip]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!strcmp(argv[1], "server")) {
        server();
    } else if (!strcmp(argv[1], "client")) {
        client(argc == 3 ? argv[2] : "127.0.0.1");
    } else {
        fprintf(stderr, "Invalid mode. Use 'server' or 'client'.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

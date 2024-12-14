/*
 Encrypted Communication using TCP/IP
 Client-Server message application in C with encryption/decryption.
 This demonstrates the use of sockets and OpenSSL AES encryption.
 See: https://wiki.openssl.org/index.php/EVP
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define PORT            8080
#define BUFFER_SIZE     1024
#define AES_KEY_SIZE    256
#define AES_BLOCK_SIZE  16

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

// Handles decryption via OpenSSL EVP
// Decrypts ciphertext using AES-256-CBC.
// Takes ciphertext, key, IV; writes decrypted message to plaintext.
// Steps:
// 1. Create decryption context (EVP_CIPHER_CTX).
// 2. Initialize decryption using EVP_DecryptInit_ex with AES-256-CBC.
// 3. Use EVP_DecryptUpdate and EVP_DecryptFinal_ex to decrypt the message.
// 4. Free decryption context.
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
	int len, plaintext_len;

	// Create decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Initialize decryption to use AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return -1;

    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;

    // Free decryption context
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Starts a server, accepts a connection, and loops to echo clients messages.
// Steps:
// 1. Creating socket, set settings
// 2. Bind socket
// 3. Listen for connections on socket
// 4. Accept a connection
// 5. Loop to recieve message, decrypt, and respond (echo)
void server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    unsigned char key[AES_KEY_SIZE / 8] = "01234567890123456789012345678901"; // 32 bytes key
    unsigned char iv[AES_BLOCK_SIZE]    = "0123456789012345";                 // 16 bytes IV

    char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE], decrypted[BUFFER_SIZE];

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

	// Set socket settings
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

	// Accept connection(s)
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
    	// Clear buffers
        memset(buffer, 0, BUFFER_SIZE);
        memset(decrypted, 0, BUFFER_SIZE);

        // Get encrypted message from client
        int valread = read(new_socket, encrypted, BUFFER_SIZE);
        if (valread <= 0) break;

        // Decrypt message
        int decrypted_len = decrypt(encrypted, valread, key, iv, decrypted);
        if (decrypted_len < 0) {
            perror("Decryption failed");
            break;
        }

        printf("Client: \"%s\"\n", decrypted);

        // Form and encrypt response
        snprintf(buffer, BUFFER_SIZE, "Received: \"%s\"", decrypted);
        int encrypted_len = encrypt((unsigned char *)buffer, strlen(buffer), key, iv, encrypted);

        // Send the encrypted response
        send(new_socket, encrypted, encrypted_len, 0);
    }
    // Close sockets
    close(new_socket);
    close(server_fd);
}

// Client main loop
void client(const char *server_ip) {
    int sock;
    struct sockaddr_in serv_addr;

    unsigned char key[AES_KEY_SIZE / 8] = "01234567890123456789012345678901"; // 32 bytes key
    unsigned char iv[AES_BLOCK_SIZE] =    "0123456789012345";                 // 16 bytes IV

    char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE], decrypted[BUFFER_SIZE];

	// Default to localhost IP
    if (!server_ip) {
        server_ip = "127.0.0.1";
        printf("No server IP provided. Using default: %s\n", server_ip);
    }

	// Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

	// Set socket settings
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

	// Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
    	// Get message from user
        printf("Enter message: ");
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
        send(sock, encrypted, encrypted_len, 0);

		// Read, decrypt server response
        memset(buffer, 0, BUFFER_SIZE);
        int valread = read(sock, encrypted, BUFFER_SIZE);
        if (valread <= 0) break;
        int decrypted_len = decrypt(encrypted, valread, key, iv, decrypted);
        if (decrypted_len < 0) {
            perror("Decryption failed");
            break;
        }
        decrypted[decrypted_len] = '\0';

		// Print server response
        printf("Server: %s\n", decrypted);
    }
	// Close socket
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server|client> [server_ip]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!strcmp(argv[1], "server")) {
        server();
    } else if (!strcmp(argv[1], "client")) {
        client(argc == 3 ? argv[2] : NULL);
    } else {
        fprintf(stderr, "Invalid mode. Use 'server' or 'client'.\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

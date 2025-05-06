#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "bio.h"
#include "shared.h"
// ... (Include the same callbacks and BIO creation code) ...

#define CERT_FILE "/Users/jacklau/Documents/workspace/github/SSL-TLS-clientserver/cert/server-cert.pem"
#define KEY_FILE "/Users/jacklau/Documents/workspace/github/SSL-TLS-clientserver/cert/server-key.pem"

int main() {
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Prepare custom BIO method (same as client)
    BIO_METHOD *udpbio_method = NULL;
    init_udp_bio(&udpbio_method);

    // 2. Create DTLS server context
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    // Add this line to set the info callback
    SSL_CTX_set_info_callback(ctx, dtls_info_callback);
    // Load certificate and private key (replace with your files)
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);

    if (!SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256")) {
        fprintf(stderr, "Error setting cipher list\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // skip client cert verify

    // 3. Create SSL object
    SSL *ssl = SSL_new(ctx);
    // 4. Create and bind UDP socket to listen for client
    UDPBIO *bdat; BIO *bio = BIO_new(udpbio_method);
    BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL);
    BIO_set_init(bio, 1);
    bdat = BIO_get_data(bio);
    bdat->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (fcntl(bdat->sock, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL) failed");
        close(bdat->sock);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(5555);
    serv.sin_addr.s_addr = INADDR_ANY;
    bind(bdat->sock, (struct sockaddr*)&serv, sizeof(serv));
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        char tmp[1500];

        // Peek or full read the first ClientHello
        ssize_t n = recvfrom(bdat->sock, tmp, sizeof(tmp), MSG_PEEK,
                            (struct sockaddr*)&client_addr, &client_len);
        if (n < 0) {
            // perror("recvfrom initial ClientHello");
            continue;
        }
        // Store it in your custom BIO state:
        bdat->peer = client_addr;
        bdat->peer_len = client_len;
        connect(bdat->sock, (struct sockaddr*)&client_addr, client_len);
        break;
    }

    // 5. Attach BIO to SSL and wait for client
    BIO_up_ref(bio);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_accept_state(ssl);

    // 6. Perform handshake (blocking)
    if (do_dtls_handshake(ssl) != 0) {
        fprintf(stderr, "Client DTLS handshake failed\n");
        return 1;
    }
    printf("DTLS server handshake completed.\n");

    // 7. Read client message
    char buf[1500];
    int len = SSL_read(ssl, buf, sizeof(buf));
    if (len > 0) {
        printf("Server received: %.*s\n", len, buf);
    }

    // 8. Send response
    const char *msg = "Hello from server";
    SSL_write(ssl, msg, strlen(msg));

    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_meth_free(udpbio_method);
    ERR_free_strings();
    EVP_cleanup();
    return 0;
}

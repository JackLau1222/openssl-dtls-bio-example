#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "bio.h"
#include "shared.h"
// ... (Include the above callbacks and BIO creation code) ...

int main() {
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Prepare custom BIO method
    BIO_METHOD *udpbio_method = NULL;
    init_udp_bio(&udpbio_method);

    // 2. Create DTLS client context
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_info_callback(ctx, dtls_info_callback);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);

    if (!SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256")) {
        fprintf(stderr, "Error setting client cipher list\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // skip verify for demo

    // 3. Create SSL object
    SSL *ssl = SSL_new(ctx);

    // 4. Create underlying UDP socket and fill server address
    UDPBIO *bdat; BIO *bio = BIO_new(udpbio_method);
    BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL); // ensure flush is set
    BIO_set_init(bio, 1);  // manually mark init (already done in create_cb)
    bdat = BIO_get_data(bio);
    // Create and "connect" the UDP socket (destination)
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
    inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr);
    // We use sendto in write cb, so we can optionally connect for convenience
    connect(bdat->sock, (struct sockaddr*)&serv, sizeof(serv));
    bdat->peer = serv;
    bdat->peer_len = sizeof(serv);

    // 5. Attach BIO to SSL (both read and write)
    BIO_up_ref(bio);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_connect_state(ssl);

    // 6. Perform handshake
    if (do_dtls_handshake(ssl) != 0) {
        fprintf(stderr, "Client DTLS handshake failed\n");
        return 1;
    }
    printf("DTLS client handshake completed.\n");

    // 7. Send application data over DTLS
    const char *msg = "Hello from client";
    SSL_write(ssl, msg, strlen(msg));

    // 8. Read response (if any)
    char buf[1500] = {0};
    int len = SSL_read(ssl, buf, sizeof(buf));
    if (len > 0) {
        printf("Client received: %.*s\n", len, buf);
    }

    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    BIO_meth_free(udpbio_method);
    ERR_free_strings();
    EVP_cleanup();
    return 0;
}

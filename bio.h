#ifndef BIO_H
#define BIO_H
/*
 * Refactored DTLS client/server to use a custom BIO via BIO_meth_set_write,
 * without a separate helper function. SSL will drive UDP via sys/socket.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "shared.h"

#define DTLS_MTU 500

/* Custom BIO context holding socket info */
typedef struct {
    int sockfd;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    unsigned char buf[1500];
    size_t buf_len;
} BIO_UDP_CTX;

static int udp_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    return 1;
}

static int udp_bio_destroy(BIO *b) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    free(ctx);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

static int udp_bio_read(BIO *b, char *out, int outlen) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    if (!ctx || ctx->sockfd < 0) {
        BIO_set_retry_read(b);
        return -1;
    }
    ssize_t ret = recvfrom(ctx->sockfd, out, outlen, 0,
                        (struct sockaddr*)&ctx->peer, &ctx->peer_len);
    if (ret < 0) {
        if (errno==EAGAIN||errno==EWOULDBLOCK) BIO_set_retry_read(b);
        return -1;
    }
    return (int)ret;

    
    // if (!ctx || ctx->buf_len == 0) return 0;
    // int tocopy = ctx->buf_len < (size_t)outlen ? ctx->buf_len : outlen;
    // memcpy(out, ctx->buf, tocopy);
    // ctx->buf_len = 0;
    // return tocopy;
}

static int udp_bio_write(BIO *b, const char *in, int inlen) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    if (!ctx || ctx->sockfd < 0) {
        BIO_set_retry_write(b);
        return -1;
    }
    int rc = sendto(ctx->sockfd, in, inlen, 0,
                    (struct sockaddr*)&ctx->peer, ctx->peer_len);
    if (rc < 0) {
        perror("udp_write_cb send");   // prints errno and message
        if (errno==EAGAIN||errno==EWOULDBLOCK) BIO_set_retry_write(b);
        return -1;
    }
    return rc;
}

static long udp_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_CTRL_DGRAM_SET_CONNECTED:
            memcpy(&ctx->peer, ptr, sizeof(ctx->peer));
            ctx->peer_len = sizeof(ctx->peer);
            return 1;
        case BIO_CTRL_DGRAM_QUERY_MTU:
            return DTLS_MTU;
        default:
            return 0;
    }
}

static void init_udp_bio(BIO_METHOD **udp_bio_method) {
    if (*udp_bio_method) return;
    *udp_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "custom_udp");
    BIO_meth_set_write(*udp_bio_method, udp_bio_write);
    BIO_meth_set_read(*udp_bio_method, udp_bio_read);
    BIO_meth_set_ctrl(*udp_bio_method, udp_bio_ctrl);
    BIO_meth_set_create(*udp_bio_method, udp_bio_create);
    BIO_meth_set_destroy(*udp_bio_method, udp_bio_destroy);
}

/* Inline in client/server setup: */
// 1. init_udp_bio();
// 2. Create socket and addr as usual
// 3. BIO *b = BIO_new(udp_bio_method);
//    BIO_UDP_CTX *ctx = calloc(1, sizeof(*ctx));
//    ctx->sockfd = sockfd;
//    memcpy(&ctx->peer, &peer_addr, sizeof(peer_addr));
//    ctx->peer_len = sizeof(peer_addr);
//    BIO_set_data(b, ctx);
//    SSL_set_bio(ssl, b, b);
//    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
//    SSL_set_mtu(ssl, DTLS_MTU);

// 4. Pump incoming UDP before SSL calls:
//    int len = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
//    ctx->buf_len = len;
//    memcpy(ctx->buf, buf, len);

// 5. Run SSL_do_handshake() loop and SSL_read()/SSL_write() as usual.

#endif
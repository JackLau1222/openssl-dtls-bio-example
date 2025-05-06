#ifndef BIO_H
#define BIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef struct {
    int sock;
    struct sockaddr_in peer;
    socklen_t peer_len;
} UDPBIO;

// Custom UDP BIO write callback
static int udp_write_cb(BIO *bio, const char *buf, int len) {
    UDPBIO *bdat = BIO_get_data(bio);
    if (!bdat || bdat->sock < 0) {
        BIO_set_retry_write(bio);
        return -1;
    }
    ssize_t ret = send(bdat->sock, buf, len, 0);
    if (ret < 0) {
        perror("udp_write_cb send");   // prints errno and message
        if (errno==EAGAIN||errno==EWOULDBLOCK) BIO_set_retry_write(bio);
        return -1;
    }
    return (int)ret;
}

static int udp_read_cb(BIO *bio, char *buf, int len) {
    UDPBIO *bdat = BIO_get_data(bio);
    if (!bdat || bdat->sock < 0) {
        BIO_set_retry_read(bio);
        return -1;
    }
    ssize_t ret = recv(bdat->sock, buf, len, 0);
    if (ret < 0) {
        if (errno==EAGAIN||errno==EWOULDBLOCK) BIO_set_retry_read(bio);
        return -1;
    }
    return (int)ret;
}


// Custom UDP BIO control callback (handle flush, etc.)
static long udp_ctrl_cb(BIO *bio, int cmd, long num, void *ptr) {
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            // Nothing special to do for flush on UDP
            return 1;
        default:
            return 0;
    }
}

// (Optional) Create callback: allocate and init UDPBIO
static int udp_create_cb(BIO *bio) {
    UDPBIO *bdat = calloc(1, sizeof(UDPBIO));
    if (!bdat) return 0;
    // Mark uninitialized fields
    bdat->sock = -1;
    bdat->peer_len = sizeof(bdat->peer);
    BIO_set_data(bio, bdat);
    BIO_set_init(bio, 1);
    return 1;
}

// (Optional) Destroy callback: free UDPBIO
static int udp_destroy_cb(BIO *bio) {
    UDPBIO *bdat = BIO_get_data(bio);
    if (bdat) {
        if (bdat->sock >= 0) close(bdat->sock);
        free(bdat);
        BIO_set_data(bio, NULL);
    }
    BIO_set_init(bio, 0);
    return 1;
}

static void init_udp_bio(BIO_METHOD **udp_bio_method) {
    if (*udp_bio_method) return;
    *udp_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "custom_udp");
    BIO_meth_set_write(*udp_bio_method, udp_write_cb);
    BIO_meth_set_read(*udp_bio_method, udp_read_cb);
    BIO_meth_set_ctrl(*udp_bio_method, udp_ctrl_cb);
    BIO_meth_set_create(*udp_bio_method, udp_create_cb);
    BIO_meth_set_destroy(*udp_bio_method, udp_destroy_cb);
}

#endif
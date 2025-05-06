#ifndef SHARED_H
#define SHARED_H

#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

// Add this new callback function near other OpenSSL helper functions
void dtls_info_callback(const SSL *ssl, int where, int ret) {
    const char *direction = "";
    const char *method = "undefined";
    if (where & SSL_CB_READ) {
        direction = "Received";
    } else if (where & SSL_CB_WRITE) {
        direction = "Sent";
    }

    if (where & SSL_ST_CONNECT)
        method = "SSL_connect";
    else if (where & SSL_ST_ACCEPT)
        method = "SSL_accept";
    
    if (where & SSL_CB_LOOP) {
        // const char *msg_type = strstr(state, "read ");
        // if (!msg_type) msg_type = strstr(state, "write ");
        // if (msg_type) {
        //     msg_type += 5;
        //     printf("DTLS %s: %.*s\n", direction, (int)(strchr(msg_type, ' ') - msg_type), msg_type);
        // }
        printf("DTLS: Info method=%s state=%s(%s), where=%d, ret=%d\n",
            method, SSL_state_string(ssl), SSL_state_string_long(ssl), where, ret);
    } else if (where & SSL_CB_ALERT) {
        method = (where & SSL_CB_READ) ? "read":"write";
        printf("DTLS: Alert method=%s state=%s(%s), where=%d, ret=%d\n",
            method, SSL_state_string(ssl), SSL_state_string_long(ssl), where, ret);
    }
}

/**
 * Pump the DTLS handshake for either client or server.
 * Returns 0 on success, -1 on fatal error.
 */
int dtls_handshake(SSL *ssl) {
    int ret, err;

    while (1) {
        ret = SSL_do_handshake(ssl);
        if (ret == 1) {
            // Handshake complete
            return 0;
        }
        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            // Underlying BIO needs more data—just loop until your socket
            // recvfrom() provides it via your udp_read_cb.
            continue;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            // BIO needs to send data—your udp_write_cb will be called
            // automatically when SSL_do_handshake calls BIO_write().
            continue;
        }
        // A real error
        fprintf(stderr, "DTLS handshake error: SSL_do_handshake() → ret=%d, err=%d\n",
                ret, err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
}


// Returns 0 on success (handshake complete), -1 on fatal error
int handshake_via_rw(SSL *ssl) {
    // A tiny dummy buffer — we send/receive zero bytes, just to pump the handshake
    static const char   dummy_tx[1] = {0};
    char                dummy_rx[1];
    int ret, err;

    while (!SSL_is_init_finished(ssl)) {
        // Try sending a zero‑length record to kick off / continue the handshake
        ret = SSL_write(ssl, dummy_tx, 0);
        if (ret <= 0) {
            err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // BIO callbacks will be invoked under the hood; retry
                continue;
            } else {
                fprintf(stderr, "[handshake] write error: %d\n", err);
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }

        // Try reading a zero‑length record to pick up peer’s handshake messages
        ret = SSL_read(ssl, dummy_rx, 0);
        if (ret <= 0) {
            err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // still handshaking, retry
                continue;
            } else {
                fprintf(stderr, "[handshake] read error: %d\n", err);
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
        // Loop until SSL_is_init_finished(ssl) becomes true
    }

    return 0;
}

/**
 * Try to send any handshake data.
 * Returns:
 *   >0   number of bytes “written” (always 0 in our zero‐length trick),
 *    0   WANT_WRITE or WANT_READ (not a fatal error),
 *   -1   fatal error.
 * On WANT_READ, you should next call dtls_recv().
 * On WANT_WRITE, you should next call dtls_send() again.
 */
int dtls_send(SSL *ssl) {
    int ret = SSL_write(ssl, NULL, 0);
    int err = SSL_get_error(ssl, ret);
    switch (err) {
      case SSL_ERROR_NONE:
        // no more handshake data pending—peer may need to read
        return 0;
      case SSL_ERROR_WANT_WRITE:
        // still more to send
        return 0;
      case SSL_ERROR_WANT_READ:
        // peer sent us something we need to read first
        return 0;
      default:
        fprintf(stderr, "[dtls_send] fatal: err=%d\n", err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

/**
 * Try to receive any handshake data.
 * Returns:
 *   >0   number of bytes “read” (always 0 here),
 *    0   WANT_READ or WANT_WRITE,
 *   -1   fatal error.
 * On WANT_WRITE, you should next call dtls_send().
 * On WANT_READ, you should next call dtls_recv() again.
 */
int dtls_recv(SSL *ssl) {
    char buf[1];
    int ret = SSL_read(ssl, buf, 0);
    int err = SSL_get_error(ssl, ret);
    switch (err) {
      case SSL_ERROR_NONE:
        // read one handshake flight, now peer may need to write
        return 0;
      case SSL_ERROR_WANT_READ:
        // still need more data from socket
        return 0;
      case SSL_ERROR_WANT_WRITE:
        // we need to send out something first
        return 0;
      default:
        fprintf(stderr, "[dtls_recv] fatal: err=%d\n", err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

// `write_turn` = 1 means start by trying to send ClientHello/ServerHello.
// After each call, you check WANT_READ/WANT_WRITE and flip accordingly.
int do_dtls_handshake(SSL *ssl) {
    int write_turn = 1;
    while (!SSL_is_init_finished(ssl)) {
        int rc;
        if (write_turn) {
            rc = dtls_send(ssl);
            if (rc < 0) return -1;
            // after sending, next we probably need to read peer reply
            write_turn = 0;
        } else {
            rc = dtls_recv(ssl);
            if (rc < 0) return -1;
            // after receiving, next we may need to send our next flight
            write_turn = 1;
        }
        // loop until SSL_is_init_finished==true
    }
    return 0;
}



#endif
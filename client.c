#include "shared.h"

#define DEST_IP "127.0.0.1"

int main(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int sockfd;
    struct sockaddr_in dest_addr, src_addr;
    char buffer[BUFSIZE];
    ssize_t sent_bytes;
    struct timeval timeout;
    socklen_t src_addr_len = sizeof(src_addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL) failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&timeout, 0, sizeof(timeout));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    if (inet_aton(DEST_IP, &dest_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid address: %s\n", DEST_IP);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    SSL* ssl = NULL;
    if (!create_ssl_session_and_bio(&ssl)) {
        exit(EXIT_FAILURE);
    }

    // Run as DTLS Client
    SSL_set_connect_state(ssl);

    // Start the handshake process
    int ssl_ret = SSL_do_handshake(ssl);

    while (1) {
        int ssl_error = SSL_get_error(ssl, ssl_ret);

        // If timeout is 0 we just started OR is time for rtx because of DTLSv1_get_timeout
        if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                BIO* write_bio = SSL_get_wbio(ssl);

                if (BIO_ctrl_pending(write_bio) < 0) {
                    fprintf(stderr, "Write BIO unexpected empty");
                    exit(EXIT_FAILURE);
                }

                // Copy data from write_bio and send via UDP
                int n = BIO_read(write_bio, buffer, BUFSIZE);
                if (n == 0) {
                    fprintf(stderr, "Write BIO unexpected empty");
                    exit(EXIT_FAILURE);
                }

                if (sendto(sockfd, buffer, n, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) != n) {
                    fprintf(stderr, "sendto failed");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
            }
        }

        if (SSL_is_init_finished(ssl))  {
            printf("Handshake Complete");
            exit(EXIT_SUCCESS);
        }

        // Populate the timeout
        if (!DTLSv1_get_timeout(ssl, &timeout)) {
            fprintf(stderr, "Get Timeout Failed");
            exit(EXIT_FAILURE);
        }

        // Schedule a RTX if timeout is 0
        if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
            if (DTLSv1_handle_timeout(ssl) < 0) {
                fprintf(stderr, "Handle Timeout Failed");
                exit(EXIT_FAILURE);
            }
        }

        // Read from socket and write to OpenSSL read BIO
        ssize_t n = recvfrom(sockfd, buffer, BUFSIZE, 0, (struct sockaddr *) &src_addr, &src_addr_len);
        if (n > 0) {
            int ssl_ret = BIO_write(SSL_get_rbio(ssl), buffer, n);
            if (ssl_ret <= 0) {
                fprintf(stderr, "BIO_write failed");
                exit(EXIT_FAILURE);
            }

            ERR_clear_error();
            ssl_ret = SSL_read(ssl, buffer, n);
            if (ssl_ret == 0 && SSL_get_error(ssl, ssl_ret) == SSL_ERROR_ZERO_RETURN) {
                printf("close_notify");
                exit(EXIT_SUCCESS);
            } else if (ssl_ret <= 0) {
                fprintf(stderr, "SSL_read failed");
                exit(EXIT_FAILURE);
            }

            memcpy(&dest_addr, &src_addr, sizeof(src_addr));
        }
    }

    return 0;
}

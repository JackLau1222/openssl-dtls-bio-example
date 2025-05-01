#include "shared.h"

#define DEST_IP "127.0.0.1"

int main(void) {
    int sockfd;
    struct sockaddr_in dest_addr;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();


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

    run(ssl, (struct sockaddr *) &dest_addr, sockfd);
    return 0;
}

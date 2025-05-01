#include "shared.h"

int main(void) {
    int sockfd;
    struct sockaddr_in server_addr, dest_addr;

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


    memset(&server_addr, 0, sizeof(server_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    SSL* ssl = NULL;
    if (!create_ssl_session_and_bio(&ssl)) {
        exit(EXIT_FAILURE);
    }

    // Run as DTLS Server
    SSL_set_accept_state(ssl);

    // Start the handshake process
    if (!SSL_do_handshake(ssl)) {
        exit(EXIT_FAILURE);
    }

    run(ssl, (struct sockaddr *) &dest_addr, sockfd);
    return 0;
}

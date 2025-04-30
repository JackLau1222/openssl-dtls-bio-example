#include "shared.h"

#define BUFSIZE 1500

int main(void) {
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();

    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFSIZE];
    socklen_t addr_len = sizeof(client_addr);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (!create_ssl_session_and_bio()) {
        exit(EXIT_FAILURE);
    }

    while (1) {
        ssize_t num_bytes = recvfrom(sockfd, buffer, BUFSIZE - 1, 0, (struct sockaddr *) &client_addr, &addr_len);
        if (num_bytes < 0) {
            perror("Error receiving data");
            continue;
        }

        buffer[num_bytes] = '\0';

        printf("Received packet from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("Data: %s\n", buffer);
    }

    close(sockfd);
    return 0;
}

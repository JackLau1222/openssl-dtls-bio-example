#include "shared.h"

#define DEST_IP "127.0.0.1"
#define MESSAGE "Hello, UDP packet!"

int main(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int sockfd;
    struct sockaddr_in dest_addr;
    ssize_t sent_bytes;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Error creating socket");
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

    if (generate_key_and_certificate()) {
        exit(EXIT_FAILURE);
    }

    // Send the UDP packet
    sent_bytes = sendto(sockfd, MESSAGE, strlen(MESSAGE), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        perror("Error sending data");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    printf("Sent %zd bytes to %s:%d\n", sent_bytes, DEST_IP, PORT);

    close(sockfd);
    return 0;
}

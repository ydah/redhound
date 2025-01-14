#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in addr;
    ssize_t n;

    if (argc != 3) {
        printf("Usage: udp_sender <dest_ip> <message>");
        return 1;
    }

    char* dest_ip = argv[1];
    char* message = argv[2];

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr(dest_ip);

    n = sendto(sock, message, 5, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (n < 1) {
        perror("sendto");
        return 1;
    }

    close(sock);

    return 0;
}

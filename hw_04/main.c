#include <sys/socket.h>
#include <netinet/in.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == -1) {
        err(EXIT_FAILURE, "server_sock");
    }

    int yes = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        err(EXIT_FAILURE, "setsockopt SO_REUSEADDR");
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        err(EXIT_FAILURE, "bind");
    }

    int backlog = 16;
    if (listen(server_sock, backlog) == -1) {
        err(EXIT_FAILURE, "listen");
    }

    for (;;) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock == -1) {
            err(EXIT_FAILURE, "accept");
        }

        char message[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello World!";
        int r = send(client_sock, message, sizeof(message) - 1, 0);
        if (r == -1) {
            err(EXIT_FAILURE, "send");
        } else if (r != sizeof(message) - 1) {
            err(EXIT_FAILURE, "send %d/%lu", r, sizeof(message) - 1);
        }

        shutdown(client_sock, SHUT_WR);

        r = -1;
        char buffer[1024];
        do {
            r = recv(client_sock, buffer, sizeof(buffer), 0);
            if (r == -1) {
                err(EXIT_FAILURE, "recv");
            }
        } while (r != 0);

        shutdown(client_sock, SHUT_RD);
        close(client_sock);
    }
}

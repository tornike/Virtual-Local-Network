
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include "server.h"
#include <rxi_log.h>
#include <vln_default_config.h>

int main(int argc, char **argv)
{
    FILE *log_f;
    // if ((log_f = fopen(VLN_LOG_FILE, "w+")) == NULL) {
    //     log_error("failed to open logging file %s error: %s", VLN_LOG_FILE,
    //               strerror(errno));
    //     exit(EXIT_FAILURE);
    // }
    log_trace("logging file opened successfully");

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        log_error(
            "error occured during creation of the child process error: %s",
            strerror(errno));
        log_debug("failed to open pipe for child error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_trace("opened pipe for child");

    char *buffer[64];
    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error(
            "error occured during creation of the child process error: %s",
            strerror(errno));
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);
        read(pipe_fds[0], buffer, 64); // temporary waiting point
    } else {
        log_trace("logging from child process");

        struct vln_network *network = malloc(sizeof(struct vln_network));

        inet_pton(AF_INET, "10.0.0.0", &network->address);
        network->address = ntohl(network->address);

        inet_pton(AF_INET, "10.0.0.255", &network->broadcast_address);
        network->broadcast_address = ntohl(network->broadcast_address);

        inet_pton(AF_INET, "255.255.255.0", &network->mask_address);
        network->mask_address = ntohl(network->mask_address);

        network->network_bits = 24;
        strcpy(network->name, "network");

        int sfd;
        struct sockaddr_in s_addr;
        sfd = socket(AF_INET, SOCK_STREAM, 0);
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(33508);
        s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) !=
            0) {
            log_error("bind failed");
            exit(EXIT_FAILURE);
        }

        start_server(network, -1, sfd);
    }

    return 0;
}
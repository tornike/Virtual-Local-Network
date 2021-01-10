
#include <arpa/inet.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "client.h"
#include "server.h"
#include <rxi_log.h>
#include <vln_adapter.h>
#include <vln_default_config.h>

#define TEST_NETWORK_NAME "test_network"

/* Function prorotypes */
static void init();

/* Global Variables */
FILE *_log_file;
struct vln_network *_network;

struct vln_network *test_network_for_server()
{
    struct vln_network *network = malloc(sizeof(struct vln_network));

    inet_pton(AF_INET, "172.6.2.0", &network->address);
    network->address = ntohl(network->address);

    inet_pton(AF_INET, "172.6.2.255", &network->broadcast_address);
    network->broadcast_address = ntohl(network->broadcast_address);

    inet_pton(AF_INET, "255.255.255.0", &network->mask_address);
    network->mask_address = ntohl(network->mask_address);

    strcpy(network->name, TEST_NETWORK_NAME);
    _network = network;
    return network;
}

uint32_t test_addr_for_client()
{
    uint32_t addr;
    inet_pton(AF_INET, "192.168.33.17", &addr);
    addr = ntohl(addr);
    return addr;
}

int test_socket_for_server()
{
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
    return sfd;
}

struct vln_adapter *test_adapter(const char *name)
{
    struct vln_adapter *adapter = vln_adapter_create(name);
    return adapter;
}

int main(int argc, char **argv)
{
    init();

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

        if (strcmp(argv[1], "s") == 0)
            start_server(test_network_for_server(), test_socket_for_server(),
                         test_adapter(TEST_NETWORK_NAME));
        else if (strcmp(argv[1], "c") == 0)
            start_client(TEST_NETWORK_NAME, test_addr_for_client(), 33508,
                         test_adapter(TEST_NETWORK_NAME));
        else
            exit(EXIT_FAILURE);
    }

    return 0;
}

static void init()
{
    if (mkdir(VLN_RUN_DIR, 0755) != 0 && errno != EEXIST) {
        log_error("could not create directory %s error: %s", VLN_RUN_DIR,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    // change dir owner

    if (mkdir(VLN_LOG_DIR, 0755) != 0 && errno != EEXIST) {
        log_error("could not create directory %s error: %s", VLN_RUN_DIR,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    // change dir owner

#ifndef DEVELOP
    struct passwd *pwd;
    struct group *grp;
    if (getpwnam(VLN_USER) == NULL) {
        log_error("failed to get info about user %s", VLN_USER);
        exit(EXIT_FAILURE);
    }
    if (getgrnam(VLN_USER) == NULL) {
        log_error("failed to get info about group %s", VLN_USER);
        exit(EXIT_FAILURE);
    }
#endif

    // Maybe not in this function
    if ((_log_file = fopen(VLN_LOG_FILE, "w+")) == NULL) {
        log_error("failed to open file %s error: %s", VLN_LOG_FILE,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_trace("%s file opened successfully", VLN_LOG_FILE);

    // change file owner
}
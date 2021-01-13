
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <libconfig.h>
#include <linux/securebits.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "client.h"
#include "server.h"
#include <rxi_log.h>
#include <vln_adapter.h>
#include <vln_default_config.h>

/* Function prorotypes */
static void init();
static void read_config();
static struct vln_network *
network_for_server(const char *name, const char *address, int network_bits);
static int socket_for_server(const char *bind_address, const char *bind_port);
static void start_server_process(struct vln_network *network, int listen_sock);
static void start_client_process(char *network_name, uint32_t raddr,
                                 uint16_t rport);

/* Global Variables */
FILE *_log_file;

int main(int argc, char **argv)
{
    init();

#ifdef DEVELOP
    if (argc == 2 && strcmp(argv[1], "s") == 0)
        read_config(VLN_SERVER_CONFIG_FILE);
    else if (argc == 2 && strcmp(argv[1], "c") == 0)
        read_config(VLN_CLIENT_CONFIG_FILE);
    else {
        log_error("incorrect arguments");
        exit(EXIT_FAILURE);
    }
#else
    read_config(VLN_CONFIG_FILE);
#endif

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        log_error(
            "error occured during creation of the child process error: %s",
            strerror(errno));
        log_debug("failed to open pipe for child error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_trace("opened pipe for child");
    log_trace("waiting on pipe");
    char buffer[64];
    read(pipe_fds[0], buffer, 64); // temporary waiting point
}

static void start_server_process(struct vln_network *network, int listen_sock)
{
    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);

        return;
    } else {
        log_trace("logging from child process");

        start_server(network, listen_sock, vln_adapter_create(network->name));
    }
}

static void start_client_process(char *network_name, uint32_t raddr,
                                 uint16_t rport)
{
    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);

        return;
    } else {
        log_trace("logging from child process");

        start_client(network_name, raddr, rport,
                     vln_adapter_create(network_name));
    }
}

/* Initializes environment as root and changes process user */
static void init()
{
    // if (mkdir(VLN_RUN_DIR, 0755) != 0 && errno != EEXIST) {
    //     log_error("could not create directory %s error: %s", VLN_RUN_DIR,
    //               strerror(errno));
    //     exit(EXIT_FAILURE);
    // }
    // change dir owner

    if (mkdir(VLN_LOG_DIR, 0755) != 0 && errno != EEXIST) {
        log_error("could not create directory %s error: %s", VLN_RUN_DIR,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    // change dir owner

#ifndef RUN_AS_ROOT
    struct passwd *pwd;
    struct group *grp;
    if ((pwd = getpwnam(VLN_USER)) == NULL) {
        log_error("failed to get info about user %s", VLN_USER);
        exit(EXIT_FAILURE);
    }
    if ((grp = getgrnam(VLN_USER)) == NULL) {
        log_error("failed to get info about group %s", VLN_USER);
        exit(EXIT_FAILURE);
    }

    chown(VLN_LOG_DIR, pwd->pw_uid, grp->gr_gid);

    /* Keep permited capabilities */
    if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS) < 0) {
        log_error("failed to set SECBIT_KEEP_CAPS flag %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (setgid(grp->gr_gid) < 0) {
        log_error("failed to change process group to %s - %s", VLN_USER,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setuid(pwd->pw_uid) < 0) {
        log_error("failed to change process user to %s - %s", VLN_USER,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Clear all capabilities but CAP_NET_ADMIN */
    cap_t caps = cap_get_proc();
    cap_value_t cap_list[1];

    cap_list[0] = CAP_SETPCAP;
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0) {
        log_error("failed to set cap flags - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (cap_set_proc(caps) < 0) {
        log_error("failed to set process capabilitites - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Unset keep permited capabilities */
    if (prctl(PR_SET_SECUREBITS, 0) < 0) {
        log_error("failed to unset SECBIT_KEEP_CAPS flag %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    cap_clear(caps);
    cap_list[0] = CAP_NET_ADMIN;
    if (cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_SET) < 0) {
        log_error("failed to set cap flags - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0) {
        log_error("failed to set cap flags - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (cap_set_proc(caps) < 0) {
        log_error("failed to set process capabilitites - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_free(caps) < 0) {
        log_error("freeing caps failed - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    cap_flag_value_t fv;
    caps = cap_get_proc();
    cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &fv);
    log_info("CAP_NET_ADMIN effective status %d", fv);
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

static void read_config(const char *config_file)
{
    config_t conf;
    config_setting_t *servers_setting, *clients_setting;

    config_init(&conf);

    if (!config_read_file(&conf, config_file)) {
        log_error("error while reading config file: %s:%d - %s",
                  config_error_file(&conf), config_error_line(&conf),
                  config_error_text(&conf));
        config_destroy(&conf);
        exit(EXIT_FAILURE);
    }

    servers_setting = config_lookup(&conf, "servers");
    if (servers_setting != NULL) {
        int count = config_setting_length(servers_setting);
        config_setting_t *server;
        const char *network_name, *network_subnet, *bind_address, *bind_port;
        for (int i = 0; i < count; ++i) {
            server = config_setting_get_elem(servers_setting, i);

            /* Proceed if all of the expected fields are present.
             */
            if (!(config_setting_lookup_string(server, "network_name",
                                               &network_name) &&
                  config_setting_lookup_string(server, "network_subnet",
                                               &network_subnet) &&
                  config_setting_lookup_string(server, "bind_address",
                                               &bind_address) &&
                  config_setting_lookup_string(server, "bind_port",
                                               &bind_port))) {
                log_error(
                    "error while reading config file: some fields are missing");
            }

            log_info("running server: %s %s %s %s", network_name,
                     network_subnet, bind_address, bind_port);

            char delim[] = "/";
            char *subnet_addr_str = strtok((char *)network_subnet, delim);
            char *network_bits_str = strtok(NULL, delim);

            struct vln_network *network = network_for_server(
                network_name, subnet_addr_str, atoi(network_bits_str));

            start_server_process(network,
                                 socket_for_server(bind_address, bind_port));
        }
    }

    clients_setting = config_lookup(&conf, "clients");
    if (clients_setting != NULL) {
        int count = config_setting_length(clients_setting);
        config_setting_t *client;
        const char *network_name, *address, *port;
        for (int i = 0; i < count; ++i) {
            client = config_setting_get_elem(clients_setting, i);

            /* Proceed if all of the expected fields are present.
             */
            if (!(config_setting_lookup_string(client, "network_name",
                                               &network_name) &&
                  config_setting_lookup_string(client, "address", &address) &&
                  config_setting_lookup_string(client, "port", &port))) {
                log_error("error while reading config file: incorrect fields");
            }

            log_info("running client: %s %s %s", network_name, address, port);

            uint32_t raddr;
            inet_pton(AF_INET, address, &raddr);
            uint16_t rport = atoi(port);
            raddr = ntohl(raddr);
            start_client_process((char *)network_name, raddr, rport);
        }
    }
}

struct vln_network *network_for_server(const char *name, const char *address,
                                       int network_bits)
{
    struct vln_network *network = malloc(sizeof(struct vln_network));

    inet_pton(AF_INET, address, &network->address);
    network->address = ntohl(network->address);

    network->broadcast_address =
        network->address + (uint32_t)pow(2, 32 - network_bits) - 1;

    network->mask_address = ((uint32_t)pow(2, network_bits) - 1)
                            << (32 - network_bits);

    strcpy(network->name, name);

    return network;
}

static int socket_for_server(const char *bind_address, const char *bind_port)
{
    uint16_t port = atoi(bind_port);

    int sfd;
    struct sockaddr_in s_addr;
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    inet_pton(AF_INET, bind_address, &s_addr.sin_addr.s_addr);

    if (bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) !=
        0) {
        log_error("bind failed - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return sfd;
}

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
#include <sys/wait.h>
#include <unistd.h>

#include "client.h"
#include "server.h"
#include <rxi_log.h>
#include <uthash.h>
#include <vln_adapter.h>
#include <vln_default_config.h>

struct vlnd_server {
    pid_t child_pid;

    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t network_addr;
    uint32_t mask_addr;
    uint32_t broadcast_addr;
    char *bind_addr;
    char *bind_port;

    UT_hash_handle hh;
};

struct vlnd_client {
    pid_t child_pid;

    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t raddr;
    uint16_t rport;

    UT_hash_handle hh;
};

/* Function prorotypes */
static void init();
static void read_config();
static int socket_for_server(const char *bind_address, const char *bind_port);
static void start_server_process(struct vlnd_server *server);
static void start_client_process(struct vlnd_client *client);
static void restart_dead_network(pid_t pid);

/* Global Variables */
FILE *_log_file;
static struct vlnd_client *_vlnd_clients;
static struct vlnd_server *_vlnd_servers;

int main(int argc, char **argv)
{
    init();

    _vlnd_clients = NULL;
    _vlnd_servers = NULL;

    if ((_log_file = fopen(VLN_LOG_FILE, "a")) == NULL) {
        log_error("failed to open file %s error: %s", VLN_LOG_FILE,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
    // log_trace("%s file opened successfully", VLN_LOG_FILE);

    log_add_fp(_log_file, LOG_TRACE);
#ifdef DEVELOP
    if (argc == 2 && strcmp(argv[1], "s") == 0)
        read_config(VLN_SERVER_CONFIG_FILE);
    else if (argc == 2 && strcmp(argv[1], "c") == 0)
        read_config(VLN_CLIENT_CONFIG_FILE);
    else {
        log_error("incorrect arguments: input c for client and s for server");
        exit(EXIT_FAILURE);
    }
#else
    log_set_quiet(true);
    read_config(VLN_CONFIG_FILE);
#endif

    int wstatus;
    pid_t pid;
    while (true) {
        pid = waitpid(-1, &wstatus, 0);
        log_debug("child with pid %d changed status %d", pid, wstatus);
        restart_dead_network(pid);
    }
}

static void restart_dead_network(pid_t pid)
{
    struct vlnd_client *client;
    HASH_FIND_INT(_vlnd_clients, &pid, client);
    if (client != NULL) {
        log_debug("restarting client %s", client->network_name);
        HASH_DEL(_vlnd_clients, client);
        start_client_process(client);
        return;
    }

    struct vlnd_server *server;
    HASH_FIND_INT(_vlnd_servers, &pid, server);
    if (server != NULL) {
        log_debug("restarting server %s", server->network_name);
        HASH_DEL(_vlnd_servers, server);
        start_server_process(server);
        return;
    }

    log_error("died unknown child process");
    log_debug("died network child process id couldn't be found");
    exit(EXIT_FAILURE);
}

static void start_server_process(struct vlnd_server *server)
{
    struct vln_adapter *adapter;
    if ((adapter = vln_adapter_create(server->network_name)) == NULL) {
        log_error("creating network adapter failed");
        exit(EXIT_FAILURE);
    }

    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);
        vln_adapter_destroy(adapter);

        server->child_pid = child_pid;
        HASH_ADD_INT(_vlnd_servers, child_pid, server);
        return;
    } else {
        log_trace("logging from child process");
        int listen_sock =
            socket_for_server(server->bind_addr, server->bind_port);
        struct vln_network network = {.address = server->network_addr,
                                      .mask_address = server->mask_addr,
                                      .broadcast_address =
                                          server->broadcast_addr};
        strcpy(network.name, server->network_name);
        start_server(&network, listen_sock, adapter);
    }
}

static void start_client_process(struct vlnd_client *client)
{
    struct vln_adapter *adapter;
    if ((adapter = vln_adapter_create(client->network_name)) == NULL) {
        log_error("creating network adapter failed");
        exit(EXIT_FAILURE);
    }

    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);
        vln_adapter_destroy(adapter);

        client->child_pid = child_pid;
        HASH_ADD_INT(_vlnd_clients, child_pid, client);
        return;
    } else {
        log_trace("logging from child process");

        start_client(client->network_name, client->raddr, client->rport,
                     adapter);
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

    char *user_to_change_to;
#ifdef DEVELOP
    user_to_change_to = getenv("SUDO_USER");
    if (user_to_change_to == NULL)
        return;
    printf("%s\n", user_to_change_to);
#else
    user_to_change_to = VLN_USER;
#endif

    struct passwd *pwd;
    struct group *grp;
    if ((pwd = getpwnam(user_to_change_to)) == NULL) {
        log_error("failed to get info about user %s", user_to_change_to);
        exit(EXIT_FAILURE);
    }
    if ((grp = getgrnam(user_to_change_to)) == NULL) {
        log_error("failed to get info about group %s", user_to_change_to);
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
            char *network_addr_str = strtok((char *)network_subnet, delim);
            char *network_bits_str = strtok(NULL, delim);

            int network_bits = atoi(network_bits_str);

            struct vlnd_server *s = malloc(sizeof(struct vlnd_server));
            strcpy(s->network_name, network_name);
            inet_pton(AF_INET, network_addr_str, &s->network_addr);
            s->network_addr = ntohl(s->network_addr);
            s->broadcast_addr =
                s->network_addr + (uint32_t)pow(2, 32 - network_bits) - 1;

            s->mask_addr = ((uint32_t)pow(2, network_bits) - 1)
                           << (32 - network_bits);
            s->bind_addr = (char *)bind_address;
            s->bind_port = (char *)bind_port;

            start_server_process(s);
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

            struct vlnd_client *c = malloc(sizeof(struct vlnd_client));
            strcpy(c->network_name, network_name);
            c->raddr = raddr;
            c->rport = rport;

            start_client_process(c);
        }
    }
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

    int optval = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
        log_error("setting socket options failed - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) !=
        0) {
        log_error("bind failed - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return sfd;
}
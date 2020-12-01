#include "../lib/tcpwrapper.h"
#include "starterprotocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <json-c/json.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void *get_disconnect_payload()
{
    uint8_t *spacket = malloc(sizeof(struct starter_packet_header));
    memset(spacket, 0, sizeof(spacket));

    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = STARTER_DISCONNECT;
    sheader->payload_length = 0;

    return spacket;
}

void *get_connect_payload(char const *argv[])
{

    if (strlen(argv[2]) > MAX_LENGTH || strlen(argv[2]) < MIN_NAME_LENGTH) {
        printf("User name length must be between %d and %d\n", MIN_NAME_LENGTH,
               MAX_LENGTH);
        return NULL;
    }

    if (strlen(argv[3]) > MAX_LENGTH || strlen(argv[3]) < MIN_PASSWORD_LENGTH) {
        printf("Password length must be between %d and %d\n",
               MIN_PASSWORD_LENGTH, MAX_LENGTH);
        return NULL;
    }
    uint8_t *spacket = malloc(sizeof(struct starter_packet_header) +
                              sizeof(struct starter_connect_payload));
    memset(spacket, 0, sizeof(spacket));
    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = STARTER_CONNECT;
    sheader->payload_length = sizeof(struct starter_connect_payload);

    struct starter_connect_payload *spayload =
        (struct starter_connect_payload *)(spacket +
                                           sizeof(
                                               struct starter_packet_header));

    strcpy(spayload->networck_name, argv[2]);
    strcpy(spayload->networck_password, argv[3]);

    return spacket;
}

void *get_create_payload(char const *argv[])
{

    if (strlen(argv[2]) > MAX_LENGTH || strlen(argv[2]) < MIN_NAME_LENGTH) {
        printf("User name length must be between %d and %d\n", MIN_NAME_LENGTH,
               MAX_LENGTH);
        return NULL;
    }

    if (strlen(argv[3]) > MAX_LENGTH || strlen(argv[3]) < MIN_PASSWORD_LENGTH) {
        printf("Password length must be between %d and %d\n",
               MIN_PASSWORD_LENGTH, MAX_LENGTH);
        return NULL;
    }

    char addr[SUBNET_MAX_SIZE];
    memset(addr, 0, SUBNET_MAX_SIZE);

    strcpy(addr, argv[4]);
    char delim[] = "/";
    char *subnet = strtok(addr, delim);
    char *bit = strtok(NULL, delim);
    if (bit == NULL) {
        printf("Subnet is incorrect\n");
        return NULL;
    }
    int bit_check = atoi(bit);
    uint32_t check_subnet;
    if (!inet_pton(AF_INET, subnet, &check_subnet) ||
        strcmp(".0", subnet + strlen(subnet) - 2) != 0 ||
        strlen(argv[4]) > SUBNET_MAX_SIZE || strlen(bit) > 2 ||
        bit_check < 27 || bit_check > 32) {
        printf("Subnet is incorrect\n");
        return NULL;
    }

    uint8_t *spacket = malloc(sizeof(struct starter_packet_header) +
                              sizeof(struct starter_create_payload));
    memset(spacket, 0, sizeof(spacket));
    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = STARTER_CREATE;
    sheader->payload_length = sizeof(struct starter_create_payload);

    struct starter_create_payload *spayload =
        (struct starter_create_payload *)(spacket +
                                          sizeof(struct starter_packet_header));

    strcpy(spayload->networck_name, argv[2]);
    strcpy(spayload->networck_password, argv[3]);

    strcpy(spayload->subnet, subnet);
    sprintf(spayload->bit, "%d", bit_check);

    return spacket;
}

int print_response(starter_packet_type type)
{
    if (type == STARTER_ERROR || type == SERVER_UNKNOWN_PACKET_TYPE) {
        printf("ERROR: Unknown Packet Type Received From Server\n");
    } else if (type == STARTER_DONE) {
        printf("Vln Client Connected\n");
    } else if (type == STARTER_EXIST) {
        printf("Vln Client Process Already Running\n");
    } else if (type == STARTER_DISCONNECT_DONE) {
        printf("Vln Client Will Be Disconnected\n");
    } else if (type == SERVER_NAME_OR_PASSWOR) {
        printf("Name Or Password Is Incorrect\n");
    } else if (type == SERVER_NETWORK_NOT_EXISTS) {
        printf("Vln Network Not Exists\n");
    } else if (type == SERVER_INSERT_ERROR) {
        printf("Vln Network Name Already Exists\n");
    } else if (type == SERVER_SUBNET_IS_FULL) {
        printf("Vln Network is Full\n");
    } else if (type == LOST_SERVER_CONNECTION) {
        printf("Lost Server Connection\n");
    } else {
        printf("ERROR: Unknown Packet Type Received From Service%d\n", type);
    }
}

int main(int argc, char const *argv[])
{
    uint8_t *spacket;
    int sock = 0;
    struct sockaddr_un addr;

    FILE *fp;
    char buffer[1024];
    struct json_object *parsed_json;
    struct json_object *installation_directory;

    struct passwd *pw = getpwuid(getuid());
    const char *homedir = pw->pw_dir;

    char configpath[strlen(homedir) + strlen("/.vln/vln.config") + 1];
    memset(configpath, 0, strlen(homedir) + strlen("/.vln/vln.config") + 1);
    strcpy(configpath, homedir);
    strcat(configpath, "/.vln/vln.config");

    fp = fopen("../../src/client/vln.config", "r");

    if (fp == NULL) {
        printf("Incorrect config\n");
        return -1;
    }
    fread(buffer, 1024, 1, fp);
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);

    json_object_object_get_ex(parsed_json, "installation_directory",
                              &installation_directory);
    if (installation_directory == NULL) {
        printf("Incorrect config\n");
        return -1;
    }

    if (argc == 4 && strcmp(argv[1], "connect") == 0) {
        spacket = get_connect_payload(argv);
    } else if (argc == 5 && strcmp(argv[1], "create") == 0) {
        spacket = get_create_payload(argv);
    } else if (argc == 2 && strcmp(argv[1], "disconnect") == 0) {
        spacket = get_disconnect_payload();
    } else {
        printf("Incorect arguments\n");
        return -1;
    }
    if (spacket == NULL) {
        return -1;
    }

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        free(spacket);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));

    char instdir[50];
    memset(instdir, 0, 50);
    strcpy(instdir, (char *)json_object_get_string(installation_directory));

    char sockpath[50];
    memset(sockpath, 0, 50);
    strcpy(sockpath, "/run/vln/");
    strcat(sockpath, "socket");

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sockpath);

    chdir(instdir);

    int s;
    if ((s = connect(sock, (struct sockaddr *)&addr,
                     sizeof(struct sockaddr_un))) < 0) {

        int pid = fork();
        if (pid < 0) {
            printf("Process creation failed\n");
        } else if (pid == 0) {
            char *argvc[1];
            argvc[0] = NULL;
            chdir(instdir);
            execv("client", argvc);
        }
        sleep(1);
        if (connect(sock, (struct sockaddr *)&addr,
                    sizeof(struct sockaddr_un)) < 0) {
            printf("Connection Failed %s\n", strerror(errno));
            free(spacket);
            return -1;
        }
    }
    struct tcpwrapper *tcpwrapper = tcpwrapper_create(sock, 1024);

    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;

    if (send_wrap(tcpwrapper, (void *)spacket,
                  sizeof(struct starter_packet_header) +
                      sheader->payload_length) != 0) {
        printf("Lost Connection\n");
    }
    free(spacket);

    printf("Sending... \n");

    struct starter_packet_header rheader;
    if (recv_wrap(tcpwrapper, (void *)&rheader,
                  sizeof(struct starter_packet_header)) != 0) {
        printf("Lost Connection\n");
        return -1;
    }

    if (rheader.type == STARTER_RESPONSE) {
        struct starter_response_payload rpayload;
        if (recv_wrap(tcpwrapper, (void *)&rpayload,
                      sizeof(struct starter_response_payload)) != 0)
            printf("Lost Connection\n");
        print_response(rpayload.type);
    } else {
        printf("ERROR: Unknown Packet Type Received %d\n", rheader.type);
    }

    close(sock);
    return 0;
}
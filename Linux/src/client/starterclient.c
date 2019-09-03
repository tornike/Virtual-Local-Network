#include "../lib/tcpwrapper.h"
#include "starterprotocol.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void *get_cancel_payload(starter_packet_type type)
{
    uint8_t *spacket = malloc(sizeof(struct starter_packet_header));

    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = type;
    sheader->payload_length = 0;

    printf("%d\n", sheader->payload_length);
    printf("%d\n", sheader->type);

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

    printf("%d\n", sheader->payload_length);
    printf("%d\n", sheader->type);
    printf("%s\n", spayload->networck_name);
    printf("%s\n", spayload->networck_password);

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

    // TODO subnet check argv[4]

    uint8_t *spacket = malloc(sizeof(struct starter_packet_header) +
                              sizeof(struct starter_create_payload));
    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = STARTER_CREATE;
    sheader->payload_length = sizeof(struct starter_create_payload);

    struct starter_create_payload *spayload =
        (struct starter_create_payload *)(spacket +
                                          sizeof(struct starter_packet_header));

    strcpy(spayload->networck_name, argv[2]);
    strcpy(spayload->networck_password, argv[3]);

    char subnet[MAX_LENGTH];
    memset(subnet, 0, MAX_LENGTH);

    strcpy(subnet, argv[4]);

    int init_size = strlen(subnet);
    char delim[] = "/";

    strcpy(spayload->subnet, strtok(subnet, delim));
    strcpy(spayload->bit, strtok(NULL, delim));

    printf("%d\n", sheader->payload_length);
    printf("%d\n", sheader->type);
    printf("%s\n", spayload->networck_name);
    printf("%s\n", spayload->networck_password);
    printf("%s\n", spayload->subnet);

    return spacket;
}

int main(int argc, char const *argv[])
{

    uint8_t *spacket;
    int sock = 0;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, PATH);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) <
        0) {
        printf("Start interface!\n"); // DOTO

        // int pid = fork();
        // if (pid < 0) {
        //     printf("Process creation failed\n");
        // } else if (pid == 0) { // Child Process
        //     char *argvc[1];
        //     argvc[0] = NULL;
        //     execv("/home/luka/Desktop/Virtual-Local-Network/Linux/build/client/"
        //           "client",
        //           argvc);
        //     printf("ERROR ERROR ERROOR\n");
        // } else {
        //     // Parent process
        //     printf("Child Pid %d\n", pid);
        // }

        sleep(3);
        if (connect(sock, (struct sockaddr *)&addr,
                    sizeof(struct sockaddr_un)) < 0) {
            printf("Connection Failed %s\n", strerror(errno));
            return -1;
        }
    }
    struct tcpwrapper *tcpwrapper = tcpwrapper_create(sock, 2048);

    if (argc == 4 && strcmp(argv[1], "connect") == 0) {
        spacket = get_connect_payload(argv);
    } else if (argc == 5 && strcmp(argv[1], "create") == 0) {
        spacket = get_create_payload(argv);
    } else if (argc == 2 && strcmp(argv[1], "disconnect") == 0) {
        spacket = get_cancel_payload(STARTER_DISCONNECT);
    } else if (argc == 2 && strcmp(argv[1], "stop") == 0) {
        spacket = get_cancel_payload(STARTER_STOP);
    } else {
        printf("Incorect arguments\n");
        return -1;
    }
    if (spacket == NULL) {
        return -1;
    }

    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;

    // if ((send(sock, spacket,
    //           sizeof(struct starter_packet_header) + sheader->payload_length,
    //           0)) < 1) {
    //     printf("\nSend Failed %s\n", strerror(errno));
    //     return -1;
    // }
    if (send_wrap(tcpwrapper, (void *)spacket,
                  sizeof(struct starter_packet_header) +
                      sheader->payload_length) != 0) {
        printf("error send_wrap connect\n");
    } else {
        printf("send_wrap connect\n");
    }
    free(spacket);

    printf("Sending... \n");

    // char buffer[BUFFER_SIZE] = {0};
    // if (recv(sock, buffer, BUFFER_SIZE, 0) < 1) {
    //     printf("\nRead Failed %s\n", strerror(errno));
    //     return -1;
    // }

    struct starter_packet_header rheader;
    if (recv_wrap(tcpwrapper, (void *)&rheader,
                  sizeof(struct starter_packet_header)) != 0)
        printf("error recv_wrap INIT \n");

    if (rheader.type == STARTER_DONE || rheader.type == STARTER_ERROR) {
        struct starter_response_payload rpayload;
        if (recv_wrap(tcpwrapper, (void *)&rpayload,
                      sizeof(struct starter_response_payload)) != 0)
            printf("error recv_wrap INIT \n");
        // TODO Rsponse Text
        printf("Status: %d\n", rpayload.type);
    } else {
        printf("ERROR: Unknown Packet Type Received %d\n", rheader.type);
    }

    close(sock);
    return 0;
}
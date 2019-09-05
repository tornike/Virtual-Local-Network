#ifndef __STARTER_PROTOCOL__
#define __STARTER_PROTOCOL__

#include <stdint.h>

#define MIN_PASSWORD_LENGTH 6
#define MIN_NAME_LENGTH 4
#define MAX_LENGTH 17
#define SUBNET_MAX_SIZE 18
#define STARTER_CREATE 60
#define STARTER_CONNECT 70
#define STARTER_DISCONNECT 80
#define STARTER_ERROR 96
#define STARTER_DONE 69
#define STARTER_EXIST 68
#define BIT 3
/* DB Protocol */
#define SERVER_ERROR 31
#define SERVER_NAME_OR_PASSWOR 19
#define SERVER_UNKNOWN_PACKET_TYPE 20
#define SERVER_CREATE 21
#define SERVER_INSERT_ERROR 22
#define SERVER_SUBNET_IS_FULL 23
#define SERVER_NETWORK_NOT_EXISTS 24

#define BUFFER_SIZE 2048

typedef uint8_t starter_packet_type;

struct starter_packet_header {
    starter_packet_type type;
    uint32_t payload_length;
} __attribute__((packed));

struct starter_response_payload {
    starter_packet_type type;
} __attribute__((packed));

struct starter_connect_payload {
    char networck_name[MAX_LENGTH];
    char networck_password[MAX_LENGTH];
} __attribute__((packed));

struct starter_create_payload {
    char networck_name[MAX_LENGTH];
    char networck_password[MAX_LENGTH];
    char subnet[MAX_LENGTH];
    char bit[BIT];
} __attribute__((packed));

#endif
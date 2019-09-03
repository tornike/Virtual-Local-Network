#ifndef __STARTER_PROTOCOL__
#define __STARTER_PROTOCOL__

#include <stdint.h>

#define PATH "/home/luka/Desktop/service/socket/socket1"
#define MIN_PASSWORD_LENGTH 6
#define MIN_NAME_LENGTH 4
#define MAX_LENGTH 16
#define STARTER_CREATE 60
#define STARTER_CONNECT 70
#define STARTER_DISCONNECT 80
#define STARTER_STOP 90
#define STARTER_ERROR 96
#define STARTER_DONE 69
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
    char bit[2];
} __attribute__((packed));

#endif
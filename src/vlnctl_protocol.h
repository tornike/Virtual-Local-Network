#ifndef __VLNCTL_PROTOCOL__
#define __VLNCTL_PROTOCOL__

#include <stdint.h>
#include <vln_constants.h>
#include <vln_types.h>

#define CREATE 1
#define ALREADY_EXISTS 2
#define CONNECT 3
#define ALREADY_CONNECTED 4
#define DISCONNECT 5
#define ERROR 6
#define DONE 7

typedef uint8_t vlnctl_packet_type;

struct vlnctl_packet_header {
    vlnctl_packet_type type;
    uint32_t payload_length;
} __VLN_PACKED;

struct vlnctl_create_payload {
    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t network_addr;
    uint32_t mask_addr;
    uint32_t host_addr;
    uint16_t host_port;
} __VLN_PACKED;

struct vlnctl_connect_payload {
    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t raddr;
    uint16_t rport;
} __VLN_PACKED;

union vlnctl_packet_payload {
    struct vlnctl_create_payload create_payload;
    struct vlnctl_connect_payload connect_payload;
} __VLN_PACKED;

#endif
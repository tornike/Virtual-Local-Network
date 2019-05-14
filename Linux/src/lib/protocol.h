#ifndef __VLN_PROTOCOL__
#define __VLN_PROTOCOL__

#include "../connection.h"
#include <stdint.h>

#define INIT 1
#define INITR 2
#define HOSTS 3
#define HOSTSR 4
#define CONNECT 5 /* Request For Connect */
#define CONNECT_ACK 6

#define ADDR 7
#define KEEPALIVE 8
#define UADDR 9

/* Flags */
#define VLN_VIRTUALADDR 128
#define VLN_SERVER 64

typedef uint8_t vln_packet_type;

struct vln_packet_header {
    vln_packet_type type;
    uint32_t payload_length;
} __attribute__((packed));

struct vln_vaddr_payload {
    uint32_t ip_addr;
    /*
        VIRTUAL ADDR, SERVER, UNUSED FLAGS ...
    */
    uint8_t flags;
} __attribute__((packed));

struct vln_uaddr_payload {
    uint16_t port;
} __attribute__((packed));

struct vln_connect_payload {
    vln_connection_type con_type;
    uint32_t vaddr;
} __attribute__((packed));

#endif

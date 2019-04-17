#ifndef __VLN_PROTOCOL__
#define __VLN_PROTOCOL__

#include <stdlib.h>

#define INIT 1
#define ADDR 2
#define KEEPALIVE 3
#define UADDR 4

typedef uint8_t VLN_PACKET_TYPE;

struct vln_packet_header {
    VLN_PACKET_TYPE type;
    uint32_t payload_length;
} __attribute__((packed));

struct vln_addr_paylod {
    uint32_t ip_addr;
} __attribute__((packed));

struct vln_uaddr_paylod {
    uint16_t port;
} __attribute__((packed));

#endif

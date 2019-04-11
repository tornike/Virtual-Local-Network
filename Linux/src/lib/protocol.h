#ifndef __VLN_PROTOCOL__
#define __VLN_PROTOCOL__

#include <stdlib.h>

#define INIT 1
#define ADDR 2

typedef uint8_t VLN_PACKET_TYPE;

struct vln_packet_header {
    VLN_PACKET_TYPE type;
    uint32_t payload_length;
} __attribute__((packed));

struct vln_addr_paylod {
    int ip_addr;
    int port;
} __attribute__((packed));

#endif

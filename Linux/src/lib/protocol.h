#ifndef __VLN_PROTOCOL__
#define __VLN_PROTOCOL__

#include <stdint.h>

#define INIT 1
#define INITS 2
#define CONNECT 3
#define CONNECTS 4
#define ADDR 5
#define KEEPALIVE 6
#define UADDR 7

#define VLN_VIRTUALADDR 128
#define VLN_SERVER 64

typedef uint8_t VLN_PACKET_TYPE;

struct vln_packet_header {
    VLN_PACKET_TYPE type;
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

#endif

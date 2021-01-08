
#ifndef __VLN_ROUTER_PROTOCOL__
#define __VLN_ROUTER_PROTOCOL__

#include <stdint.h>

#define __VLN_PACKED __attribute__((packed))

typedef uint8_t router_packet_type;

#define INIT 1
#define KEEPALIVE 2
#define DATA 3

struct router_packet_header {
    router_packet_type type;
} __VLN_PACKED;

struct router_init_payload {
    uint32_t vaddr; /* Addr of init sender */
} __VLN_PACKED;

struct router_keepalive_payload {
    uint32_t vaddr; /* Addr of keepalive sender */
} __VLN_PACKED;

#define ROUTER_PACKET_PAYLOAD(packet)                                          \
    ((uint8_t *)packet + sizeof(struct router_packet_header))

#endif
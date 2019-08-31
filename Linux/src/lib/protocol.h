#ifndef __VLN_PROTOCOL__
#define __VLN_PROTOCOL__

#include "../connection.h"
#include <stdint.h>

#define INIT 1
#define INITR 2
#define HOSTS 3
#define HOSTSR 4
#define CONNECT 5 /* Request For Connect */

#define ADDR 8
#define KEEPALIVE 9
#define UADDR 10
#define DATA 11
#define RETRANSMIT 12
#define ROOTNODE 13
#define UPDATES 14
#define UPDATEDIS 15

/* Flags */
#define VLN_VIRTUALADDR 128
#define VLN_SERVER 64

typedef uint8_t vln_packet_type;

struct vln_packet_header {
    vln_packet_type type;
    uint32_t payload_length; // TODO endian
} __attribute__((packed));

/// vadr real adry real port
struct vln_updates_payload {
    uint32_t svaddr;
    uint32_t dvaddr;
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;
} __attribute__((packed));

struct vln_update_payload {
    uint32_t svaddr;
    uint32_t sraddr;
    uint16_t srport;
    uint32_t dvaddr;
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;
} __attribute__((packed));

struct vln_updatedis_payload {
    uint32_t vaddr;
} __attribute__((packed));

struct vln_initr_payload {
    uint32_t vaddr;
    uint32_t maskaddr;
    uint32_t broadaddr;
} __attribute__((packed));

struct vln_vaddr_payload {
    uint32_t ip_addr;
    /*
        VIRTUAL ADDR, SERVER, UNUSED FLAGS ...
    */
    uint8_t flags;
} __attribute__((packed));

// TODO
struct vln_addr_payload {
    uint32_t raddr;
    uint16_t port;
} __attribute__((packed));

// TODO
struct vln_rootnode_payload {
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;
} __attribute__((packed));

// struct vln_server_connect_payload { /* Connect packet payload for server */
//     vln_connection_type con_type;
//     uint32_t vaddr;
// } __attribute__((packed));

// struct vln_connect_payload { /* Connect packet payload for client */
//     vln_connection_type con_type;
//     uint32_t vaddr; /* visac unda daukavshirdes */
//     uint32_t raddr; /* razec unda gaugzavnos traffici */
//     uint16_t rport;
// } __attribute__((packed));

struct vln_data_packet_header {
    vln_packet_type type;
} __attribute__((packed));

struct vln_data_init_payload {
    uint32_t vaddr; /* Addr of init sender */
} __attribute__((packed));

struct vln_data_keepalive_payload {
    uint32_t vaddr; /* Addr of keepalive sender */
} __attribute__((packed));

#define PACKET_PAYLOAD(packet)                                                 \
    ((uint8_t *)packet + sizeof(struct vln_packet_header))

#define DATA_PACKET_PAYLOAD(packet)                                            \
    ((uint8_t *)packet + sizeof(struct vln_data_packet_header))

#endif

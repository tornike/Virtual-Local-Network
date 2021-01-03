/*
 * Nonblocking packet buffer
 */

#ifndef __VLN_NBP_MANAGER__
#define __VLN_NBP_MANAGER__

#include "../lib/protocol.h"
#include <stddef.h>

typedef enum mngr_packet_state {
    Waiting_Header,
    Waiting_Payload,
    Ready
} mngr_packet_state_t;

typedef union vln_packet_payload {
    struct vln_error_payload error_payload;
    struct vln_updates_payload updates_payload;
    struct vln_updatedis_payload updatedis_payload;
    struct vln_init_payload init_payload;
    struct vln_vaddr_payload vaddr_payload;
    struct vln_addr_payload addr_payload;
    struct vln_rootnode_payload rootnode_payload;
    struct vln_connect_payload connect_payload;
    struct vln_create_payload create_payload;
} vln_packet_payload_t;

struct mngr_packet_status {
    mngr_packet_state_t state;
    struct vln_packet_header *header;
    void *payload;
    size_t left_bytes;
    void *buffer_pos;

    uint8_t __buffer[sizeof(struct vln_packet_header) +
                     sizeof(vln_packet_payload_t)];
};

void initialize_packet(struct mngr_packet_status *p);
void reset_packet(struct mngr_packet_status *p);
void read_packet(int sock_fd, struct mngr_packet_status *p);

#endif
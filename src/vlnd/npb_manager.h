/*
 * Nonblocking packet buffer
 */

#ifndef __VLN_NPB_MANAGER__
#define __VLN_NPB_MANAGER__

#include "mngr_protocol.h"
#include <stddef.h>

typedef enum { Waiting_Header, Waiting_Payload, Ready } mngr_packet_state_t;

struct mngr_packet_status {
    mngr_packet_state_t state;
    struct mngr_packet_header *header;
    void *payload;
    size_t left_bytes;
    void *buffer_pos;

    uint8_t __buffer[sizeof(struct mngr_packet_header) +
                     sizeof(union mngr_packet_payload)];
};

void initialize_packet(struct mngr_packet_status *p);
void reset_packet(struct mngr_packet_status *p);
void read_packet(int sock_fd, struct mngr_packet_status *p);

#endif
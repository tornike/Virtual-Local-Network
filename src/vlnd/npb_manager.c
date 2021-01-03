
#include <arpa/inet.h>
#include <errno.h>
#include <rxi_log.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "npb_manager.h"

void initialize_packet(struct mngr_packet_status *p)
{
    p->header = (struct vln_packet_header *)p->__buffer;
    p->payload = PACKET_PAYLOAD(p->__buffer);

    reset_packet(p);
}

void reset_packet(struct mngr_packet_status *p)
{
    p->state = Waiting_Header;
    p->buffer_pos = p->__buffer;
    p->left_bytes = sizeof(struct vln_packet_header);
}

void read_packet(int sock_fd, struct mngr_packet_status *p)
{
    ssize_t read_bytes;
read_packet:
    read_bytes = recv(sock_fd, p->buffer_pos, p->left_bytes, MSG_DONTWAIT);
    if (read_bytes < 0) {
        log_error("packet_status: error reading socket error: %s",
                  strerror(errno));
        return;
    }
    p->buffer_pos += read_bytes;
    p->left_bytes -= read_bytes;

    switch (p->state) {
    case Waiting_Header:
        if (p->left_bytes == 0) {
            p->state = Waiting_Payload;
            p->left_bytes = ntohl(p->header->payload_length);
            p->buffer_pos = p->payload;
            goto read_packet;
        } else {
            log_trace("packet_status: not enough bytes");
            break;
        }
    case Waiting_Payload:
        if (p->left_bytes == 0) {
            p->state = Ready;
            p->left_bytes = -1;
            p->buffer_pos = NULL;
        } else {
            log_trace("packet_status: not enough bytes");
            break;
        }
    case Ready:
        break;
    default:
        log_error("packet_status: unknown state");
        exit(EXIT_FAILURE);
    }
}

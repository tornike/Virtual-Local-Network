#ifndef __VLN_HOST__
#define __VLN_HOST__

#include "npb_manager.h"
#include <stdint.h>
#include <uthash.h>

struct vln_host {
    uint32_t vaddr;
    uint32_t udp_addr;
    uint32_t udp_port;
    int sock_fd;

    struct mngr_packet_status rpacket;

    UT_hash_handle hh;
};

#endif
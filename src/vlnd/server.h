#ifndef __VLN_SERVER__
#define __VLN_SERVER__

#include <vln_constants.h>

struct vln_network {
    char name[NETWORK_NAME_MAX_LENGTH];
    uint32_t address;
    uint32_t mask_address;
    uint32_t broadcast_address;
    uint8_t network_bits;
};

void start_server(struct vln_network *network, const int nic_fd,
                  const int listening_sock);

#endif

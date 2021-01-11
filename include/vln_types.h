#ifndef __VLN_TYPES__
#define __VLN_TYPES__

#include <stdint.h>
#include <vln_constants.h>

#define __VLN_PACKED __attribute__((packed))

struct vln_network {
    char name[NETWORK_NAME_MAX_LENGTH];
    uint32_t address;
    uint32_t mask_address;
    uint32_t broadcast_address;
};

#endif
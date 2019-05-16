#ifndef __VLN_CONNECTION__
#define __VLN_CONNECTION__

#include <stdint.h>

/* Connection types */
#define PYRAMID 1

typedef uint8_t vln_connection_type;

struct connection {
    vln_connection_type con_type;
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;
    int timerfds;
    int timerfdr;
};

#endif
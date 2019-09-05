#ifndef __VLN_ADAPTER__
#define __VLN_ADAPTER__

#include <stdint.h>

#define ADAPTER_NAME "testint1"
#define ADAPTER_NAME_SIZE 17

struct vln_adapter {
    int fd;
    char name[ADAPTER_NAME_SIZE];
};

struct vln_adapter *vln_adapter_create(int flags);

void vln_adapter_destroy(struct vln_adapter *);

int vln_adapter_set_network(struct vln_adapter *adapter, uint32_t vaddr,
                            uint32_t maskaddr, uint32_t broadaddr);

#endif
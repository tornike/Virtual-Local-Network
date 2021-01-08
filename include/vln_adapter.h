#ifndef __VLN_ADAPTER__
#define __VLN_ADAPTER__

#include <linux/if.h>
#include <stdint.h>
#include <vln_types.h>

#define VLN_ADAPTER_NAME_SIZE IFNAMSIZ

struct vln_adapter {
    int fd;
    char name[VLN_ADAPTER_NAME_SIZE];
};

struct vln_adapter *vln_adapter_create(const char *name);

void vln_adapter_destroy(struct vln_adapter *);

int vln_adapter_set_network(struct vln_adapter *adapter, uint32_t addr,
                            uint32_t maskaddr, uint32_t broadaddr);

void vln_adapter_set_network2(struct vln_adapter *adapter,
                              struct vln_network *network, uint32_t vaddr);

#endif
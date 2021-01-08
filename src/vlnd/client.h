#ifndef __VLN_CLIENT__
#define __VLN_CLIENT__

#include <vln_adapter.h>
#include <vln_types.h>

void start_client(const char *network_name, const uint32_t server_addr,
                  const uint16_t server_port, struct vln_adapter *adapter);

#endif
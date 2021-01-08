#ifndef __VLN_SERVER__
#define __VLN_SERVER__

#include <vln_adapter.h>
#include <vln_types.h>

void start_server(struct vln_network *network, const int listening_sock,
                  struct vln_adapter *adapter);

#endif

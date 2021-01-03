#ifndef __VLN_EPOLL_EVENT__
#define __VLN_EPOLL_EVENT__

typedef enum vln_descriptor_type {
    Host_Socket,
    Router_Pipe,
    Listen_Socket
} vln_descriptor_type;

typedef union vln_epoll_data {
    void *ptr;
    int fd;
} vln_epoll_data_t;

struct vln_epoll_event {
    vln_descriptor_type type;
    vln_epoll_data_t data;
};

#endif

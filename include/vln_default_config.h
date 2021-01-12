#ifndef __VLN_DEFAULT_CONFIG__
#define __VLN_DEFAULT_CONFIG__

#define VLN_USER "vlnd"

#define __VLN_LOG_FILENAME "vln.log"
#define __VLN_CONFIG_FILENAME "vln.conf"
#define __VLN_SOCK_FILENAME "vln.socket"

#ifdef DEVELOP
#define VLN_CONFIG_DIR "../etc/"
#define VLN_LOG_DIR "log/"
#define VLN_RUN_DIR "run/"
#define __VLN_CLIENT_CONFIG_FILENAME "vln_client.conf"
#define __VLN_SERVER_CONFIG_FILENAME "vln_server.conf"
#define VLN_CLIENT_CONFIG_FILE VLN_CONFIG_DIR __VLN_CLIENT_CONFIG_FILENAME
#define VLN_SERVER_CONFIG_FILE VLN_CONFIG_DIR __VLN_SERVER_CONFIG_FILENAME
#else
#define VLN_CONFIG_DIR "/etc/vln/"
#define VLN_LOG_DIR "/var/log/vln/"
#define VLN_RUN_DIR "/run/vln/"
#endif

#define VLN_LOG_FILE VLN_LOG_DIR __VLN_LOG_FILENAME
#define VLN_CONFIG_FILE VLN_CONFIG_DIR __VLN_CONFIG_FILENAME
#define VLN_SOCK_FILE VLN_RUN_DIR __VLN_SOCK_FILENAME

#endif
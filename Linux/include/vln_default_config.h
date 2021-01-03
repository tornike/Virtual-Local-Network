#ifndef __VLN_DEFAULT_CONFIG__
#define __VLN_DEFAULT_CONFIG__

#define VLN_CONFIG_FILENAME "vln.conf"
#define VLN_LOG_FILENAME "vln.log"

#ifdef DEVELOP
#define VLN_CONFIG_DIR "../../etc/"
#define VLN_LOG_DIR "../../build/"
#else
#define VLN_CONFIG_DIR "/etc/vln/"
#define VLN_LOG_DIR "/var/log/vln/"
#endif

#define VLN_LOG_FILE VLN_LOG_DIR VLN_LOG_FILENAME

#endif
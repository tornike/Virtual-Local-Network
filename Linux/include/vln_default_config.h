#ifndef __VLN_DEFAULT_CONFIG__
#define __VLN_DEFAULT_CONFIG__

#define CONFIG_FILE "vln.conf"

#ifdef DEVELOP
#define CONFIG_DIR "../etc/"
#else
#define CONFIG_DIR "/etc/vln/"
#endif

#endif
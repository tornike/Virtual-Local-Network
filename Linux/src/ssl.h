#ifndef __VLN_SSL__
#define __VLN_SSL__

#include <openssl/err.h>
#include <openssl/ssl.h>

void get_certificates(SSL_CTX *ctx, char *file, char *key);
SSL_CTX *init_cCTX();
SSL_CTX *init_sCTX();

#endif
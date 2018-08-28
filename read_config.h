#ifndef _READ_CONFIG_H
#define _READ_CONFIG_H
#include "libnss_ufp.h"

typedef struct _certificate_config_t {
    char *certificate_filename;
    char *key_filename;
    char *key_passphrase;
    char *truststore_filename;
} certificate_config_t;

void read_config(config_t *config, certificate_config_t *certificate_config);
void free_config(config_t *config);
void free_certificate_config(certificate_config_t *certificate_config);
#endif /* _READ_CONFIG_H */

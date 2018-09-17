#include <ctype.h>
#include <stdio.h>
#include <identity.h>
#include <errno.h>
#include "strmap.h"
#include "read_config.h"

/* for security reasons */
#define MIN_UID_NUMBER   500
#define MIN_GID_NUMBER   500

#ifndef TEST
#define CONF_FILE "/etc/libnss-ufp.conf"
#else
#define CONF_FILE "./test.config"
#endif

#define DEFAULT_SHELL "/bin/bash"
#define DEFAULT_HOME "/home/%s"
#define DEFAULT_GATE "/var/run/sshd.pid"

void get_certificate_config(StrMap *sm, certificate_config_t *certificate_config);
void override_default_config(StrMap *sm, config_t *config);

long check_number(char *str) {
    char *endptr;
    long val;

    errno = 0;    /* To distinguish success/failure after call */
    val = strtol(str, &endptr, 10);

    /* Check for various possible errors */

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
        perror("strtol");
        return -1;
    }

    if (endptr == str) {
        return -1;
    }

    return val;
}

char *trim(char *untrimmed) {
    char *trimmed = NULL;
    if (untrimmed != NULL) {
        char *s = untrimmed;
        while (isspace((unsigned char) *s) && (*s != '\0'))
            s++;
        char *p = untrimmed + strlen(untrimmed);
        while (p > s && (isspace((unsigned char) *p) || *p == '\0'))
            p--;
        if (p-s > 0) {
            int size = (p-s) + 2;
            trimmed = malloc(sizeof(char)*size);
            memset(trimmed, 0, sizeof(char)*size);

            for (int index = 0; index < size-1; index++) {
                trimmed[index]=*s;
                s++;
            }
        }
    }
    return trimmed;
}

char *allocate(const char *string) {
    char *buffer = malloc(strlen(string) + 1);
    memset(buffer, 0, strlen(string) + 1);
    strcpy(buffer, string);
    return buffer;
}

char *get_value(StrMap *sm, const char *key)
{
    int size = sm_get(sm, key, NULL, 0);
    char *buffer = NULL;
    if (size > 0) {
        buffer = malloc(size);
        sm_get(sm, key, buffer, size);
    }
    return buffer;
}

void read_config(config_t *config, certificate_config_t *certificate_config)
{
    FILE *fd;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    if ((fd = fopen(CONF_FILE, "r")) == NULL ) {
        return; // we have to have the config for the certificate stuff
    }

    char *key;
    char *value;
    const char delimeter[2] = "=";

    StrMap *sm = sm_new(20);

    while ((read = getline(&line, &len, fd)) != -1) {
        if (isspace(line[strlen(line)-1]))
            line[strlen(line) - 1] = '\0';

        if (line[0] == '#' || isspace(line[0]))
            continue;
        else if (strchr(line, '=') != NULL) {
            key = strtok(line, delimeter);
            value = strtok(NULL, delimeter);
            char *key_trimmed = trim(key);
            char *value_trimmed = trim(value);

            if ((key_trimmed != NULL) && (value_trimmed != NULL))
                sm_put(sm, key_trimmed, value_trimmed);

            if (key_trimmed != NULL)
                free(key_trimmed);
            if (value_trimmed != NULL)
                free(value_trimmed);
        }
    }
    free(line);

    if (config != NULL) {
        // preinitialize
        config->pw_uid_base = MIN_UID_NUMBER;
        config->uid_to_gid = 1;
        config->pw_dir = allocate(DEFAULT_HOME);
        config->pw_shell = allocate(DEFAULT_SHELL);
        config->gate = allocate(DEFAULT_GATE);
        config->gid_count = 0;
        get_certificate_config(sm, certificate_config);
        override_default_config(sm, config);
    }
    sm_delete(sm);
    fclose(fd);
}

void get_certificate_config(StrMap *sm, certificate_config_t *certificate_config) {
    if (certificate_config != NULL) {
        certificate_config->certificate_filename = get_value(sm, "certificate.file");
        certificate_config->key_filename = get_value(sm, "key.file");
        certificate_config->key_passphrase = get_value(sm, "key.passphrase");
        certificate_config->truststore_filename = get_value(sm, "truststore.file");
    }
    return;
}

void free_certificate_config(certificate_config_t *certificate_config) {
    if (certificate_config != NULL) {
        free(certificate_config->certificate_filename);
        free(certificate_config->key_filename);
        free(certificate_config->key_passphrase);
        free(certificate_config->truststore_filename);
    }
}

void override_default_config(StrMap *sm, config_t *config) {
    char *value = get_value(sm, "base.uid");
    if (value != NULL) {
        config->pw_uid_base = atoi(value);
        free(value);
    }

    value = get_value(sm, "default.home");
    if (value != NULL) {
        free(config->pw_dir);
        config->pw_dir = value;
        // don't free
    }

    value = get_value(sm, "default.shell");
    if (value != NULL) {
        free(config->pw_shell);
        config->pw_shell = value;
        // don't free
    }

    value = get_value(sm, "gate");
    if (value != NULL) {
        free(config->gate);
        config->gate = value;
        // don't free
    }

    value = get_value(sm, "gid.list");
    if (value != NULL) {
        int count = 0;
        // first we have to count
        char *element = strtok(value, ",");
        while (element != NULL) {
            long number = check_number(element);
            if (number > -1) {
                count++;
            }
            element = strtok(NULL, ",");
        }
        config->pw_gids = (gid_t *)malloc(count * sizeof(gid_t));
        config->gid_count = count;
        free(value);
        // now run through them
        value = get_value(sm, "gid.list");
        count = 0;

        int uid_to_gid = 0;
        element = strtok(value, ",");
        while (element != NULL) {
            if (strncmp(element, "uid", 3) == 0) {
                uid_to_gid = 1;
            } else {
                long number = check_number(element);
                if (number > -1) {
                    config->pw_gids[count++] = number;
                }
            }
            element = strtok(NULL, ",");
        }
        free(value);
        config->uid_to_gid = uid_to_gid;
    }
}

void free_config(config_t *config) {
    if (config != NULL) {
        free(config->pw_dir);
        free(config->pw_shell);
        free(config->gate);
        if (config->pw_gids != NULL)
            free(config->pw_gids);
    }
}



#ifdef TEST
int main(int argc, char *argv[]) {
    config_t config;
    certificate_config_t certificate_config;
    read_config(&config, &certificate_config);
    printf("got config -> uid_base : %d, uid_to_gid : %d, pw_dir : %s, pw_shell : %s\n",
           config.pw_uid_base,
           config.uid_to_gid,
           config.pw_dir,
           config.pw_shell);
    printf("\tlist of %d gids\n", config.gid_count);
    if (config.gid_count > 0) {
        int i = 0;
        for (i = 0; i < config.gid_count; i++) {
            printf("\t\t%d\n", config.pw_gids[i]);
        }
    }
    free_config(&config);
    free_certificate_config(&certificate_config);
    return 0;
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strmap.h>

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

int main(void)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    const char delimeter[2] = "=";
    char *key;
    char *value;

    StrMap *sm = sm_new(20);

    fp = fopen("test.config", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1) {
        printf("Retrieved line of length %zu :\n", read);
        if (isspace(line[strlen(line)-1]))
            line[strlen(line) - 1] = '\0';

        printf("%s\n", line);
        if (line[0] == '#') 
            continue;
        else if (strchr(line, '=') != NULL) {
            key = strtok(line, delimeter);
            value = strtok(NULL, delimeter);
            printf("found key %s, with value %s\n", key, value);
            sm_put(sm, key, value);
        }
    }

    char *v;
    v = get_value(sm, "key.passphrase");
    free(v);
    v = get_value(sm, "key.file");
    free(v);

    fclose(fp);
    if (line)
        free(line);
    sm_delete(sm);
    exit(EXIT_SUCCESS);
}

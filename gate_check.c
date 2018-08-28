#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glob.h>

#include "gate_check.h"

int check_gate(const char *gate) {
    int i, ret = 1;
    int flags = 0;
    glob_t results;

    ret = glob(gate, flags, NULL, &results);
    if (ret == 0) {
        struct stat file_stat;
        if (stat(results.gl_pathv[0], &file_stat) == 0) {
            if ((time(NULL) - file_stat.st_mtime) <  1)
                ret = 1;
        }
    }
    globfree(&results);
    return ret;
}

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

int main (int argc, char *argv[]) {
    struct passwd *ent = NULL;

    printf ("ent struct is %d bytes\n", sizeof(*ent));
    FILE *stream = fmemopen(argv[1], strlen(argv[1])+1, "r");

    ent = fgetpwent(stream);
    if (ent != NULL) {
        printf ("pointer is %p, user is %s, uid is %d, gid is %d\n", ent, ent->pw_name, ent->pw_uid, ent->pw_gid);
    } else
        perror("fgetpwent");
    return 0;
}

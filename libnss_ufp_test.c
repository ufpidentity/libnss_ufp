#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <shadow.h>

struct spwd *getspnam(const char *name);

int main (int argc, char *argv[]){

	struct passwd *p;
	struct spwd *s;

	char *usern="pippo.pluto";

	if(argc ==2)
	{
		usern=argv[1];
	}

	if (!(p=getpwnam(usern))) {
		return -1;
	}

    size_t buflen = 1024;
    char buffer[buflen];
    struct passwd *otherp;

    int index = 0;
    while (getpwnam_r(usern, p, buffer, buflen, &otherp) != 0) {
        printf("loop %d\n", index++);
        if (errno != ERANGE) {
            break;
        }
    }

	printf("FROM PASSWORD:\n");

	printf("\tname:  %s\n", p->pw_name);
	printf("\tdir:   %s\n", p->pw_dir);
    printf("\tuid:   %d\n", p->pw_uid);
    printf("\tgid:   %d\n", p->pw_gid);
	printf("\tshell: %s\n", p->pw_shell);
    printf("\tgecos: %s\n", p->pw_gecos);

	printf("FROM SHADOW:\n");

	if (!(s = getspnam(usern))) {
		return -1;
	}

	printf ("\tname:  %s\n", s->sp_namp);
	printf ("\tpass:  %s\n", s->sp_pwdp);

	return 0;

}

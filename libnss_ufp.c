#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <identity.h>
#include <identity-openssl-bridge.h>

#include "libnss_ufp.h"
#include "read_config.h"
#include "gate_check.h"

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#if HAVE_PTHREAD
static pthread_mutex_t ufp_nss_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

struct group *find_group(gid_t gid) {
    struct group *g = NULL;
    FILE *groups = fopen("/etc/group", "r");
    if (groups != NULL) {
        g = fgetgrent(groups);
        while (g != NULL) {
            if (g->gr_gid == gid) {
                break;
            }
            g = fgetgrent(groups);
        }
        fclose(groups);
    }
    return g;
}

/*
 * Allocate some space from the nss static buffer.  The buffer and buflen
 * are the pointers passed in by the C library to the _nss_ntdom_*
 * functions.
 *
 *  Taken from glibc
 */
static char *
get_static(char **buffer, size_t *buflen, int len)
{
    char *result;

    /* Error check.  We return false if things aren't set up right, or
     * there isn't enough buffer space left. */

    if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
        return NULL;
    }

    /* Return an index into the static buffer */

    result = *buffer;
    *buffer += len;
    *buflen -= len;

    return result;
}

static unsigned strsize(const char *str) {
	return strlen(str) + 1;
}

static config_t __config =
    {
        0,
        0,
        NULL,
        NULL,
        NULL,
        0,
        NULL
    };

static certificate_config_t __identity_config =
    {
        NULL,
        NULL,
        NULL,
        NULL
    };

static identity_context_t *identity_context;

/* Fill a pwent structure from a response from the service.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return NSS_STATUS_TRYAGAIN if we run out of memory. */

static enum nss_status fill_pwent(struct passwd *result,
                                  struct passwd *pw,
                                  char **buffer, size_t *buflen)
{
	/* User name */
	if ((result->pw_name =
	     get_static(buffer, buflen, strsize(pw->pw_name))) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_name, pw->pw_name);

	/* Password */

	if ((result->pw_passwd =
	     get_static(buffer, buflen, strsize(pw->pw_passwd))) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_passwd, pw->pw_passwd);

	/* [ug]id */

	result->pw_uid = pw->pw_uid;
	result->pw_gid = pw->pw_gid;

	/* GECOS */

	if ((result->pw_gecos =
	     get_static(buffer, buflen, strsize(pw->pw_gecos))) == NULL) {
		/* Out of memory */
		return NSS_STATUS_TRYAGAIN;
	}
	strcpy(result->pw_gecos, pw->pw_gecos);

	/* Home directory */

    int length = snprintf(NULL, 0, __config.pw_dir, result->pw_name) + 1;
	if ((result->pw_dir =
	     get_static(buffer, buflen, length + 1)) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}
    snprintf(result->pw_dir, length, __config.pw_dir, result->pw_name);

	/* Logon shell */

	if ((result->pw_shell =
	     get_static(buffer, buflen, strsize(__config.pw_shell))) == NULL) {

		/* Out of memory */

		return NSS_STATUS_TRYAGAIN;
	}

	strcpy(result->pw_shell, __config.pw_shell);

	/* The struct passwd for Solaris has some extra fields which must
	   be initialised or nscd crashes. */

#if HAVE_PASSWD_PW_COMMENT
	result->pw_comment = "";
#endif

#if HAVE_PASSWD_PW_AGE
	result->pw_age = "";
#endif

	return NSS_STATUS_SUCCESS;
}

void
_nss_ufp_init(void) {
    openlog("libnss_ufp", LOG_PID, LOG_AUTH);
    syslog(LOG_DEBUG|LOG_AUTH, "%s", __func__);
    read_config(&__config, &__identity_config);
    identity_context = get_identity_context(__identity_config.certificate_filename,
                                            __identity_config.truststore_filename,
                                            __identity_config.key_filename,
                                            __identity_config.key_passphrase);
}

void
_nss_ufp_fini (void)
{
    free_config(&__config);
    free_certificate_config(&__identity_config);
    free_identity_context(identity_context);
    syslog(LOG_DEBUG|LOG_AUTH, "%s", __func__);
    closelog();
}

enum nss_status
_nss_ufp_getpwuid_r( uid_t uid,
                     struct passwd *p,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    char temp[16];
    StrMap *sm = sm_new(10);
    snprintf(temp, 16, "%d", uid);
    sm_put(sm, "uid", temp);
    sm_put(sm, "type", "passwd");

    syslog(LOG_DEBUG|LOG_AUTH, "%s %d", __func__, uid);
    char *entry = management_find(identity_context, sm);

    if (entry != NULL) {
        struct passwd *passwd;
        FILE *stream = fmemopen(entry, strsize(entry), "r");

        passwd = fgetpwent(stream);
        free(entry);
        if (passwd != NULL) {
            p->pw_name = get_static(&buffer, &buflen, strsize(passwd->pw_name));
            if (p->pw_name)
                strcpy(p->pw_name, passwd->pw_name);

            p->pw_passwd = get_static(&buffer, &buflen, strsize(passwd->pw_passwd));
            if (p->pw_passwd)
                strcpy(p->pw_passwd, passwd->pw_passwd);

            p->pw_shell = get_static(&buffer, &buflen, strsize(__config.pw_shell));
            if (p->pw_shell)
                strcpy(p->pw_shell, __config.pw_shell);

            int length = snprintf(NULL, 0, __config.pw_dir, passwd->pw_name) + 1;
            p->pw_dir = get_static(&buffer, &buflen, length);
            if (p->pw_dir)
                snprintf(p->pw_dir, length, __config.pw_dir, passwd->pw_name);

            p->pw_uid = passwd->pw_uid;
            p->pw_gid = passwd->pw_gid;

            if (p->pw_name && p->pw_passwd && p->pw_shell && p->pw_dir)
                status =  NSS_STATUS_SUCCESS;
            else {
                *errnop = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
            }
        }
        fclose(stream);
    } else
        *errnop = errno = 0;
    return status;
}
struct passwd *g_passwd;

enum nss_status
_nss_ufp_getpwnam_r( const char *name,
                     struct passwd *p,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    if ((strcmp(name, "*") == 0) || (strcmp(name, p->pw_name) == 0)) {
        *errnop = errno = 0;
        return NSS_STATUS_SUCCESS;
    }

#if HAVE_PTHREAD
	pthread_mutex_lock(&ufp_nss_mutex);
#endif
    syslog(LOG_DEBUG|LOG_AUTH, "%s %s", __func__, name);
    enum nss_status status = NSS_STATUS_NOTFOUND;

    if (check_gate(__config.gate) == 0) {
        if ((g_passwd == NULL) || (strcmp(g_passwd->pw_name, name) != 0)) {
            StrMap *sm = sm_new(10);

            sm_put(sm, "name", name);
            char temp[16];
            snprintf(temp, 16, "%d", __config.pw_uid_base);
            sm_put(sm, "uidbase", temp);
            if (__config.uid_to_gid == 1 || __config.gid_count == 0) {
                sm_put(sm, "gidbase", temp);
            } else {
                snprintf(temp, 16, "%d", __config.pw_gids[0]); // first one
                if (find_group(__config.pw_gids[0]) != NULL)
                    sm_put(sm, "gid", temp);
                else
                    sm_put(sm, "gidbase", temp);
            }

            syslog(LOG_DEBUG|LOG_AUTH, "%s %s", __func__, name);

            char *entry = management(identity_context, sm);

            if (entry != NULL) {
                FILE *stream = fmemopen(entry, strsize(entry), "r");
                g_passwd = fgetpwent(stream);
                free(entry);

                if (g_passwd != NULL) {
                    status = fill_pwent(p, g_passwd, &buffer, &buflen);
                    fclose(stream);
                    if (status == NSS_STATUS_TRYAGAIN) {
                        *errnop = errno = ERANGE;
                        goto done;
                    }
                    *errnop = errno = 0;

                }
            }
        } else {
            status = fill_pwent(p, g_passwd, &buffer, &buflen);
            if (status == NSS_STATUS_TRYAGAIN) {
                *errnop = errno = ERANGE;
                goto done;
            }
            *errnop = errno = 0;
        }
    }
    done:
#if HAVE_PTHREAD
	pthread_mutex_unlock(&ufp_nss_mutex);
#endif
    return status;
}

enum nss_status
_nss_ufp_getspnam_r( const char *name,
                     struct spwd *s,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    syslog(LOG_DEBUG|LOG_AUTH, "%s %s", __func__, name);
    s->sp_namp = get_static(&buffer, &buflen, strsize(name));
    if (s->sp_namp)
        strcpy(s->sp_namp, name); /* pw_name stay as the name given */

    s->sp_pwdp = get_static(&buffer, &buflen, 2);
    if (s->sp_pwdp)
        snprintf(s->sp_pwdp, 2, "*");

    if (s->sp_namp && s->sp_pwdp)
        return NSS_STATUS_SUCCESS;

    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
}

enum nss_status
_nss_ufp_getgrent_r( struct group *g,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    *errnop = ENOENT;

    if (check_gate(__config.gate) == 0) {
        if (__config.gid_count > 0) {
            int i, n;
            struct group *group = NULL;
            for (i = 0; i < __config.gid_count; i++) {
                if (g->gr_gid == __config.pw_gids[i])
                    break;
            }
            if (i == __config.gid_count - 1) { // we're at the end and found so return no more
                *errnop = ENOENT;
                return NSS_STATUS_NOTFOUND;
            }

            if (i == __config.gid_count) // were at the end and not found so start at beginning
                n = 0;
            else
                n = i+1;

            for (i = n; i < __config.gid_count; i++) {
                group = find_group(__config.pw_gids[i]);
                if (group != NULL) {
                    g->gr_gid = group->gr_gid;

                    g->gr_name = get_static(&buffer, &buflen, strsize(group->gr_name));
                    if (g->gr_name)
                        strcpy(g->gr_name, group->gr_name);

                    g->gr_passwd = get_static(&buffer, &buflen, strsize(group->gr_passwd));
                    if (g->gr_passwd)
                        strcpy(g->gr_passwd, group->gr_passwd);

                    StrMap *sm = sm_new(10);
                    sm_put(sm, "type", "group");

                    char *entry = management_find(identity_context, sm);
                    int count = 0;
                    if (entry != NULL) {
                        struct group *grp;
                        FILE *stream = fmemopen(entry, strsize(entry), "r");

                        grp = fgetgrent(stream);
                        while (grp != NULL) {
                            count++;
                            grp = fgetgrent(stream);
                        }
                        if (count > 0) {
                            rewind(stream);
                            g->gr_mem = (char **)get_static(&buffer, &buflen, sizeof(char *) * (count+1));
                            if (g->gr_mem) {
                                int index;

                                for (index = 0; index < count; index++) {
                                    grp = fgetgrent(stream);
                                    if (grp != NULL) {
                                        g->gr_mem[index] = get_static(&buffer, &buflen, strsize(grp->gr_name));
                                        if (g->gr_mem[index])
                                            strcpy(g->gr_mem[index], grp->gr_name);
                                    }
                                }
                                *(g->gr_mem+count) = NULL;
                            }
                        } else {
                            *errnop = ENOENT;
                            status = NSS_STATUS_UNAVAIL;
                        }
                        fclose(stream);
                        free(entry);
                    }
                    if (count > 0) {
                        if (g->gr_name && g->gr_passwd && g->gr_mem)
                            status = NSS_STATUS_SUCCESS;
                        else {
                            status = NSS_STATUS_TRYAGAIN;
                            *errnop = ERANGE;
                        }
                        break;
                    }
                }
            }
        }
    }
    return status;
}

enum nss_status
_nss_ufp_getgrgid_r( const gid_t gid,
                     struct group *g,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    char temp[16];
    StrMap *sm = sm_new(10);
    snprintf(temp, 16, "%d", gid);
    sm_put(sm, "gid", temp);
    sm_put(sm, "type", "passwd");
    syslog(LOG_DEBUG|LOG_AUTH, "%s %d", __func__, gid);
    char *entry = management_find(identity_context, sm);

    if (entry != NULL) {
        struct passwd *passwd;
        FILE *stream = fmemopen(entry, strsize(entry), "r");

        passwd = fgetpwent(stream);
        free(entry);
        if (passwd != NULL) {
            g->gr_name = get_static(&buffer, &buflen, strsize(passwd->pw_name));
            if (g->gr_name)
                strcpy(g->gr_name, passwd->pw_name);

            g->gr_passwd = get_static(&buffer, &buflen, 2);
            if (g->gr_passwd)
                snprintf(g->gr_passwd, 2, "*");

            g->gr_gid = gid;



            if (g->gr_name && g->gr_passwd)
                status =  NSS_STATUS_SUCCESS;
            else {
                *errnop = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
            }
        }
        fclose(stream);
    }
    return status;
}

enum nss_status
_nss_ufp_getgrnam_r( const char *name,
                     struct group *g,
                     char *buffer,
                     size_t buflen,
                     int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;

    if (check_gate(__config.gate) == 0) {
        StrMap *sm = sm_new(10);
        sm_put(sm, "type", "group");
        syslog(LOG_DEBUG|LOG_AUTH, "%s %s - %s", __func__, name, g->gr_name);

        char *entry = management_find(identity_context, sm);

        if (entry != NULL) {
            struct group *grp;
            FILE *stream = fmemopen(entry, strsize(entry), "r");

            grp = fgetgrent(stream);
            while (grp != NULL) {
                if (strncmp(grp->gr_name, name, strlen(name)) == 0)
                    break;
                grp = fgetgrent(stream);
            }
            if (grp != NULL) { // we found one
                g->gr_name = get_static(&buffer, &buflen, strsize(name));
                if (g->gr_name)
                    strcpy(g->gr_name, name); /* name is what's passed in */

                g->gr_passwd = get_static(&buffer, &buflen, 2);
                if (g->gr_passwd)
                    snprintf(g->gr_passwd, 2, "*");

                if (g->gr_name && g->gr_passwd)
                    status = NSS_STATUS_SUCCESS;
                else {
                    *errnop = ERANGE;
                    status = NSS_STATUS_TRYAGAIN;
                }
            } else {
                status = NSS_STATUS_NOTFOUND;
            }
            fclose(stream);
            free(entry);
        } else
            *errnop = errno = 0;
    }
    return status;
}

#ifndef _LIBNSS_UFP_H
#define _LIBNSS_UFP_H
typedef struct config {
    uid_t  pw_uid_base;
    int    uid_to_gid;
    char   *pw_dir;        /* home directory */
    char   *pw_shell;      /* shell program */
    char   *gate;          /* gate file for serving requests */
    int    gid_count;
    gid_t  *pw_gids;
} config_t;
#endif /* _LIBNSS_UFP_H */

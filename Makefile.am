lib_LTLIBRARIES = libnss_ufp.la
libnss_ufp_la_SOURCES = libnss_ufp.c gate_check.c read_config.c strmap.c
libnss_ufp_la_LDFLAGS = "-Wl,-init,_nss_ufp_init,-fini,_nss_ufp_fini" -release `ldd --version | head -n1 | cut -d " " -f5`
ACLOCAL_AMFLAGS=-I m4
libnss_ufp_la_CFLAGS = ${UFPIDENTITY_CFLAGS}
libnss_ufp_la_LIBADD = ${UFPIDENTITY_LIBS}
super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile

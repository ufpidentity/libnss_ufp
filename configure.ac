AC_PREREQ(2.61)
m4_define([glibc_version], m4_esyscmd_s([ldd --version | head -n1 | cut -d " " -f5]))
AC_INIT([libnss_ufp], glibc_version, [richardl@ufp.com])
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([libnss_ufp.c], [gate_check.c], [read_config.c], [strmap.c])
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE 

AC_PROG_CC
AC_PROG_CC_STDC

PKG_PROG_PKG_CONFIG([0.26])
AX_CHECK_COMPILE_FLAG([-Wno-unused-result], [CFLAGS="$CFLAGS -Wno-unused-result"]) 
PKG_CHECK_MODULES([UFPIDENTITY], [ufpidentity >= 1.1],,)
soname_spec='${libname}${shared_ext}.`echo glibc_version | cut -d . -f 1`'
library_names_spec='${libname}${release}${shared_ext}$versuffix ${libname}${release}${shared_ext}$major ${libname}${shared_ext}.`echo glibc_version | cut -d . -f 1`'
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"

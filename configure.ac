AC_INIT(configure.ac)
AM_INIT_AUTOMAKE(spg, 0.1)
AM_CONFIG_HEADER(config.h)

AC_LANG_C
AC_PROG_CC
AM_PROG_LIBTOOL

PKG_CHECK_MODULES(libcrypto, [libcrypto >= 0.9])
AC_SUBST(libcrypto_CFLAGS)
AC_SUBST(libcrypto_LIBS)
AC_CHECK_LIB(gcrypt, gcry_mpi_new, [], [
        echo "Error! gcrypt library not found."
        exit -1
        ])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ftfd], [1.0.0], [tomas.cejka@fit.cvut.cz])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE(silent-rules)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [pcap_create])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT64_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

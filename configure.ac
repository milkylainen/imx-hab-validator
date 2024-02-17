#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([imx-hab-validator], [1.0], [christian.melki@westermo.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/csf-validate-imx8.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O
AC_C_INLINE

# Checks for libraries.
PKG_CHECK_MODULES(CRYPTO, openssl)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h unistd.h openssl/ssl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap strncasecmp])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

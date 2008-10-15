#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([spider-engine],[1.1.0],[nock@email.arizona.edu])
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_SRCDIR([spider.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h strings.h sys/file.h sys/time.h syslog.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero ftruncate gethostname pow regcomp strcasecmp strerror strrchr strstr flock])

# See if the user wants to link statically
AC_ARG_ENABLE(dynamic,
    [AC_HELP_STRING([--enable-dynamic],[disable static linking of the the spider binary])])
if test "$enable_dynamic" = "yes"; then
  AC_SUBST([STATIC],[ ])
else
  AC_SUBST([STATIC],[-static])
fi

# Checks for libraries.
AC_ARG_ENABLE(bzlib,
    [AC_HELP_STRING([--enable-bzlib],[enable scanning the content of bz2 files])])
if test "$enable_bzlib" = "yes"; then
  AC_CHECK_LIB([bz2], [BZ2_bzopen],[],[AC_MSG_ERROR([Cannot locate libbz2])])
  AC_CHECK_HEADER([bzlib.h],[],[AC_MSG_ERROR([Cannot locate bzip2 header; install bzip2-devel?])])
else
  AC_CHECK_LIB([bz2], [BZ2_bzopen],[],[AC_MSG_WARN([Cannot locate libbz2; scanning bzip2 files disabled])])
  AC_CHECK_HEADER([bzlib.h],[],[AC_MSG_WARN([Cannot locate bzip2 header; install bzip2-devel?])])
fi

AC_CHECK_LIB([crypto], [SSLeay],[],[AC_MSG_ERROR([Cannot locate required library: libcrypto])])

AC_CHECK_LIB([dl], [main])

AC_CHECK_LIB([expat], [XML_ParserReset],[],[AC_MSG_ERROR([Cannot locate required library: libexpat])])

AC_CHECK_LIB([m], [exp],[],[AC_MSG_ERROR([Cannot locate required library: libm])])

AC_ARG_ENABLE(magic,
  [AC_HELP_STRING([--enable-magic],[enable enhanced file typing with libmagic])])
if test "$enable_magic" = "yes"; then
  AC_CHECK_LIB([magic], [magic_file],[],[AC_MSG_ERROR([Cannot locate libmagic])])
  AC_CHECK_HEADER([magic.h],[],[AC_MSG_ERROR([Cannot locate libmagic headers; install file-devel?])])
else
  AC_CHECK_LIB([magic], [magic_file],[],[AC_MSG_WARN([Cannot locate libmagic; enhance file typing disabled])])
  AC_CHECK_HEADER([magic.h],[],[AC_MSG_WARN([Cannot locate libmagic headers; install file-devel?])])
fi

AC_CHECK_LIB([pcre], [pcre_config],,AC_MSG_ERROR(Cannot locate required library: pcre))

AC_CHECK_LIB([ssl], [main],,AC_MSG_ERROR(Cannot locate required library: ssl))

AC_ARG_ENABLE(deflate,
  [AC_HELP_STRING([--enable-deflate],[enable scanning of deflated files])])
if test "$enable_deflate" = "yes"; then
  AC_CHECK_LIB([z], [gzopen],[],[AC_MSG_ERROR([Cannot locate libz])])
  AC_CHECK_HEADER([zlib.h],[],[AC_MSG_ERROR([Cannot locate libz headers; install zlib-devel?])])
else
  AC_CHECK_LIB([z], [gzopen],[],[AC_MSG_WARN([Cannot locate libz; Scanning deflate files disabled])])
  AC_CHECK_HEADER([zlib.h],[],[AC_MSG_WARN([Cannot locate libz headers; install zlib-devel?])])
fi

#AC_CHECK_LIB([zzip], [main],,AC_MSG_WARN(Scanning zip files disabled))
AC_ARG_ENABLE(zip,
  [AC_HELP_STRING([--enable-zip],[enable scanning of zipped files])])
if test "$enable_zip" = "yes"; then
  AC_CHECK_LIB([zzip], [zzip_dir_open],[],[AC_MSG_ERROR([Cannot locate libzzip])])
  AC_CHECK_HEADER([zzip.h],[],[AC_MSG_ERROR([Cannot locate libz headers])])
else
  AC_CHECK_LIB([zzip], [zzip_dir_open],[],[AC_MSG_WARN([Cannot locate zzip; Scanning zip files disabled])])
  AC_CHECK_HEADER([zzip.h],[],[AC_MSG_WARN([Cannot locate libzzip headers])])
fi

AC_PREFIX_DEFAULT([/opt/common/spider-1.0])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.69])
#AC_INIT([scalpel],[3.6.9],[golden@cct.lsu.edu])
AC_INIT([foo], m4_bregexp(m4_quote(m4_include([src/scalpelv.h])), [[0-9]+\.[0-9]+\.[0-9]+], [\&]))


AC_MSG_NOTICE([scalpel3 version is $PACKAGE_VERSION])
AC_MSG_NOTICE([Using library path $LDFLAGS])

: ${CFLAGS=""}
AC_CONFIG_SRCDIR([src])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])
LT_INIT
#AC_CONFIG_HEADERS([config.h])
AC_PROG_INSTALL
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_PROG([gettext],[gettext],[yes],[no])
AM_CONDITIONAL([FOUND_GETTEXT], [test "x$gettext" = xyes])
AM_COND_IF([FOUND_GETTEXT],,[AC_MSG_ERROR([scalpel3 requires 'gettext'.])])

AC_PROG_CC
AC_CHECK_PROG([xmlto],[xmlto],[yes],[no])
AM_CONDITIONAL([FOUND_XMLTO], [test "x$xmlto" = xyes])
AM_COND_IF([FOUND_XMLTO],,[AC_MSG_ERROR([scalpel3 requires 'xmlto'.])])

AC_PROG_CC
AC_CHECK_PROG([pkg_config],[pkg-config],[yes],[no])
AM_CONDITIONAL([FOUND_PKGCONFIG], [test "x$pkg_config" = xyes])
AM_COND_IF([FOUND_PKGCONFIG],,[AC_MSG_ERROR([scalpel3 requires 'pkg-config'.])])


# ---- FUSE (blockmapfs)
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([FUSE], [fuse3], [], [
  PKG_CHECK_MODULES([FUSE], [fuse], [], [
    AC_MSG_ERROR([FUSE not found (tried fuse3, fuse).])
  ])
])

AC_SUBST([FUSE_CFLAGS])
AC_SUBST([FUSE_LIBS])

# MPI compiler (required for hpcscalpel3)
# AC_ARG_VAR allows MPICC to be set via environment
AC_ARG_VAR([MPICC], [MPI C compiler (defaults to mpicc if not set)])
# Only search PATH if MPICC wasn't already provided
if test -z "$MPICC"; then
  AC_CHECK_PROG([MPICC], [mpicc], [mpicc], [])
fi
AS_IF([test -n "$MPICC"], [have_mpi=yes], [have_mpi=no])
AM_CONDITIONAL([HAVE_MPI], [test "x$have_mpi" = "xyes"])
AC_SUBST([MPICC])

# Extract MPI compile flags so gcc can find MPI headers for hpcscalpel3;
# linking uses @MPICC@ directly via hpcscalpel3_LINK in Makefile.am.
MPI_CFLAGS=""
if test "x$have_mpi" = "xyes"; then
    # OpenMPI
    MPI_CFLAGS=`$MPICC --showme:compile 2>/dev/null`
    # MPICH (newer)
    test -z "$MPI_CFLAGS" && \
        MPI_CFLAGS=`$MPICC -compile-info 2>/dev/null | sed 's/^[[^ ]]* //'`
    # MPICH (older) / Intel MPI
    test -z "$MPI_CFLAGS" && \
        MPI_CFLAGS=`$MPICC -compile_info 2>/dev/null | sed 's/^[[^ ]]* //'`
    AC_MSG_NOTICE([MPI compile flags: $MPI_CFLAGS])
fi
AC_SUBST([MPI_CFLAGS])

# SDL2 (required for diskviz)
PKG_CHECK_MODULES([SDL2], [sdl2], [], [AC_MSG_ERROR([diskviz requires SDL2. Install libsdl2-dev.])])
PKG_CHECK_MODULES([SDL2_IMAGE], [SDL2_image], [], [AC_MSG_ERROR([diskviz requires SDL2_image. Install libsdl2-image-dev.])])
PKG_CHECK_MODULES([SDL2_TTF], [SDL2_ttf], [], [AC_MSG_ERROR([diskviz requires SDL2_ttf. Install libsdl2-ttf-dev.])])

# Checks for libraries.
AC_CHECK_LIB([m], [fabs])
AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [], [AC_MSG_ERROR(scalpel3 requires 'libssl'.)])
AC_CHECK_LIB([crypto], [CRYPTO_new_ex_data], [], [AC_MSG_ERROR([scalpel3 requires 'libcrypto'.])])
AC_CHECK_LIB([z], [compress2], [], [AC_MSG_ERROR([scalpel3 requires a libz-compatible 'zlib-ng'.])])
AC_SEARCH_LIBS([jpeg_finish_decompress], [jpegturbo turbojpeg jpeg], [], [AC_MSG_ERROR(scalpel3 requires 'libjpeg-turbo'.)])
AC_CHECK_LIB([png], [png_set_mem_fn], [], [AC_MSG_ERROR(scalpel3 requires 'libpng'.)])
AC_CHECK_LIB([pcre2-8], [pcre2_match_8], [], [AC_MSG_ERROR(scalpel3 requires 'libpcre2'.)])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR(scalpel3 requires 'libpthread'.)])
AC_CHECK_LIB([dl], [dlclose], [], [AC_MSG_ERROR(scalpel3 requires 'libdl'.)])
AC_CHECK_LIB([elf], [elf_begin], [], [AC_MSG_ERROR(scalpel3 requires 'libelf'.)])
AC_CHECK_LIB([backtrace], [backtrace_create_state], [], [AC_MSG_ERROR(scalpel3 requires 'libbacktrace'.)])
AC_CHECK_LIB([mpg123], [mpg123_format], [], [AC_MSG_ERROR(scalpel3 requires 'mpg123'.)])
AC_CHECK_LIB([archive], [archive_read_open_memory], [], [AC_MSG_ERROR(scalpel3 requires 'libarchive'.)])
AC_CHECK_LIB([pocketfft_mdct], [pfft_mdctf_init], [], [AC_MSG_ERROR(error compiling pocketfft_mdct.cpp)])

# ---- ONNX Runtime (required for ELF ONNX inference)
AC_LANG_PUSH([C++])
AC_CHECK_HEADER([onnxruntime_cxx_api.h], [],
  [AC_MSG_ERROR([scalpel3 requires ONNX Runtime headers (onnxruntime_cxx_api.h). Install ORT and ensure CPPFLAGS includes -I/path/to/onnxruntime/include])])
AC_LANG_POP([C++])

saved_LIBS="$LIBS"
AC_CHECK_LIB([onnxruntime], [OrtGetApiBase], [],
  [AC_MSG_ERROR([scalpel3 requires libonnxruntime. Install ORT and ensure LDFLAGS/LIBS include it.])])
LIBS="$saved_LIBS"


# Checks for header files.
AC_CHECK_HEADERS([ctype.h sys/stat.h fcntl.h limits.h stddef.h stdlib.h string.h sys/ioctl.h sys/mount.h sys/param.h sys/time.h time.h sys/timeb.h unistd.h sys/file.h errno.h stdarg.h stdint.h math.h stdbool.h pthread.h inttypes.h stdatomic.h locale.h openssl/sha.h sys/socket.h sys/un.h execinfo.h backtrace.h pcre2.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_FSEEKO
#AC_FUNC_MALLOC
#AC_FUNC_MMAP
#AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gettimeofday mkdir realpath regcomp strchr strdup strerror strncasecmp strtoul strtoull memset clock_gettime])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])

AC_OUTPUT

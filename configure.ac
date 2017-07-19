dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.50)
AC_INIT(autoenc.c)
PACKAGE=autoenc

dnl version number
MAJOR_VERSION=1
MINOR_VERSION=0
MICRO_VERSION=1
INTERFACE_AGE=0
BINARY_AGE=0
EXTRA_VERSION=
BUILD_REVISION=5
VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION$EXTRA_VERSION

dnl set $target
AC_CANONICAL_SYSTEM

dnl
AM_INIT_AUTOMAKE($PACKAGE, $VERSION, no-define)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Define to the name of this package.])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Define to the version of this package.])
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(MICRO_VERSION)
AC_SUBST(BUILD_REVISION)

dnl Specify a header configuration file
AM_CONFIG_HEADER(config.h)

dnl AM_MAINTAINER_MODE

dnl Checks for programs.
dnl AC_ARG_PROGRAM
AC_PROG_CC
AM_DISABLE_STATIC
AC_ISC_POSIX
AM_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_CPP
dnl AC_PROG_RANLIB
AM_PROG_LIBTOOL

native_win32=no

case "$target" in
*-darwin*)
	CFLAGS="$CFLAGS -no-cpp-precomp -fno-common"
	;;
*-*-mingw*)
	native_win32=yes
	CFLAGS="$CFLAGS -mms-bitfields -mwindows"
	LIBS="$LIBS -lws2_32"
	AC_CHECK_PROG(WINDRES, windres, windres)
	;;
esac

AM_CONDITIONAL(NATIVE_WIN32, test "$native_win32" = "yes")

dnl Checks for libraries.
AM_PATH_GLIB_2_0(2.8.0,, AC_MSG_ERROR(Test for GLib failed. See the 'INSTALL' for help.), gobject gmodule)
AM_PATH_GTK_2_0(2.8.0,, AC_MSG_ERROR(Test for Gtk failed. See the 'INSTALL' for help.))

dnl --disable-deprecated switch for GTK2 purification
AC_ARG_ENABLE(deprecated, [  --disable-deprecated    Disable deprecated GTK functions. ],
			  [GTK_CFLAGS="$GTK_CFLAGS -DG_DISABLE_DEPRECATED -DGTK_DISABLE_DEPRECATED"], [])

AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

GTHREAD_CFLAGS="`$PKG_CONFIG --cflags gthread-2.0`"
GTHREAD_LIBS="`$PKG_CONFIG --libs gthread-2.0`"

AC_SUBST(GTHREAD_CFLAGS)
AC_SUBST(GTHREAD_LIBS)

dnl checks for iconv
AM_ICONV

AC_CHECK_FUNCS(bind_textdomain_codeset)

dnl for gettext
ALL_LINGUAS="ja"
GETTEXT_PACKAGE=autoenc
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Define text domain.])

AM_GLIB_GNU_GETTEXT
dnl AM_GNU_GETTEXT
dnl AC_CHECK_FUNC(gettext, AC_CHECK_LIB(intl, gettext))

if test "x$DATADIRNAME" != "x"; then
	localedir='${prefix}/${DATADIRNAME}/locale'
else
	localedir='${datadir}/locale'
fi
AC_ARG_WITH(localedir,
	[  --with-localedir=DIR    Locale directory],
	[localedir="$withval"])
AC_SUBST(localedir)

manualdir='${datadir}/sylpheed/manual'
AC_ARG_WITH(manualdir,
	[  --with-manualdir=DIR    Manual directory],
	[manualdir="$withval"])
AC_SUBST(manualdir)

plugindir='${exec_prefix}/lib/sylpheed/plugins'
AC_ARG_WITH(plugindir,
	[  --with-plugindir=DIR    Plug-in directory],
	[plugindir="$withval"])
AC_SUBST(plugindir)

AC_ARG_WITH(libsylph,
            [AC_HELP_STRING([--with-libsylph=DIR],
                            [search for LibSylph in DIR/include/sylpheed and DIR/lib])],
            [if test "x$with_libsylph" != x; then
                CPPFLAGS="$CPPFLAGS -I$with_libsylph/include/sylpheed"
                LDFLAGS="$LDFLAGS -L$with_libsylph/lib"
             fi])

lsb_release_id=`lsb_release -i -s`
lsb_release_rel=`lsb_release -r -s`
if test "x$lsb_release_id" = "xUbuntu" && test "x$lsb_release_rel" = "x14.04"; then
  AC_DEFINE(HAVE_BROKEN_GTK_ITEM_FACTORY, 1, Define if GtkItemFactory should not be used for menus)
fi

AC_CHECK_LIB(sylph-0, syl_init, LIBSYLPH_LIBS="-lsylph-0", AC_MSG_ERROR(Test for LibSylph failed.))
AC_CHECK_LIB(sylpheed-plugin-0, syl_plugin_init_lib, LIBSYLPHEED_PLUGIN_LIBS="-lsylpheed-plugin-0", AC_MSG_ERROR(Test for LibSylpheed-Plugin failed.))

AC_SUBST(LIBSYLPH_LIBS)
AC_SUBST(LIBSYLPHEED_PLUGIN_LIBS)

dnl check additional libraries
AC_CHECK_LIB(xpg4, setlocale)
AC_CHECK_LIB(resolv, res_init)
AC_CHECK_LIB(socket, bind)
AC_CHECK_LIB(nsl, gethostbyname)

dnl for GThread support in plug-in
AC_ARG_ENABLE(threads,
	[  --enable-threads        Enable multithread support [[default=yes]]],
	[use_threads=$enableval], [use_threads=yes])

AC_MSG_CHECKING([whether to use threads])
if test x"$use_threads" = xyes ; then
	AC_MSG_RESULT(yes)
	if $PKG_CONFIG --exists gthread-2.0 ; then
		CFLAGS="$CFLAGS $GTHREAD_CFLAGS"
		LIBS="$LIBS $GTHREAD_LIBS"
		AC_DEFINE(USE_THREADS, 1, Whether to use multithread or not)
	else
		AC_MSG_ERROR([Sylpheed Pro requires GThread from GLib to enable threading.])
	fi
else
	AC_MSG_RESULT(no)
fi

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h sys/file.h unistd.h paths.h \
		 sys/param.h sys/utsname.h sys/select.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

AC_CHECK_SIZEOF(time_t)

if test "x$ac_cv_sizeof_time_t" = "x8"; then
	AC_DEFINE(HAVE_64BIT_TIME_T, 1, Define if time_t is 64-bit)
fi

dnl Checks for library functions.
AC_FUNC_ALLOCA
AC_CHECK_FUNCS(gethostname mkdir mktime strstr strchr \
	       uname fchmod truncate getuid fsync)

AC_OUTPUT([
Makefile
po/Makefile.in
])

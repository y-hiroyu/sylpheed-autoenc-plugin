libdir = $(plugindir)

SUBDIRS = po

lib_LTLIBRARIES = autoenc.la

autoenc_la_SOURCES = autoenc.c autoenc.h
autoenc_la_LDFLAGS = -module -no-undefined -avoid-version

AM_CPPFLAGS = \
	-DLOCALEDIR=\""$(localedir)"\" \
	$(GTK_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTHREAD_CFLAGS) \
        -I$(includedir) \
        -I$(includedir)/sylpheed \
        -I$(includedir)/sylpheed/sylph

autoenc_la_LIBADD = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBSYLPH_LIBS) \
	$(LIBSYLPHEED_PLUGIN_LIBS)

BUILT_SOURCES = \
	send_enc.h

EXTRA_DIST = \
	COPYING \
	README \
	autogen.sh \
	makewin32.sh \
	send_enc.png \
	$(BUILT_SOURCES)

%.h: %.png
	gdk-pixbuf-csource --name=`echo $(*F)|sed s/-/_/g` $< > $@

#install:
#install-plugin: install-am

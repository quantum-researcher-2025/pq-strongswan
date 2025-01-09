AM_CPPFLAGS = \
	-I${linux_headers} \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tcpd.la
else
plugin_LTLIBRARIES = libstrongswan-tcpd.la
endif

libstrongswan_tcpd_la_SOURCES = \
	tcpd_socket.h tcpd_socket.c \
	tcpd_plugin.h tcpd_plugin.c

libstrongswan_tcpd_la_LDFLAGS = -module -avoid-version

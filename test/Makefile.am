AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS = ruijieAS
ruijieAS_SOURCES = ruijie_auth_service.c config_control.c global.c authentication.c dbus_monitor.c 
ruijieAS_LDADD = -lglib-2.0 -lpcap -lnet -lssl -lxml2 
ruijieAS_CPPFLAGS =`pkg-config --cflags --libs glib-2.0 gthread-2.0 libxml-2.0`
ruijieAS_LDFLAGS= -lxml2
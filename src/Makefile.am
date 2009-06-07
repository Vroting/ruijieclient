AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS = ruijieclient
ruijieclient_SOURCES = blog.c codeconv.h myerr.c ruijieclient.h sendpacket.h blog.h global.h  myerr.h codeconv.c ruijieclient.c sendpacket.c conn_monitor.c conn_monitor.h
ruijieclient_LDADD = -lpcap -lnet -lssl -lxml2
ruijieclient_CFLAGS = -I /usr/include/libxml2

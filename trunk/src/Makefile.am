AUTOMAKE_OPTIONS = foreign


noinst_PROGRAMS = libpcap.so

libpcap_so_LDFLAGS = -lpcap -shared 
libpcap_so_SOURCES =

bin_PROGRAMS = ruijieclient
ruijieclient_SOURCES = blog.c codeconv.h myerr.c ruijieclient.h  \
		sendpacket.h blog.h global.h  myerr.h codeconv.c ruijieclient.c sendpacket.c \
		 conn_monitor.c conn_monitor.h prase.c prase.h md5.c md5.h \
		 config.c 

ruijieclient_LDADD = -L. 
		 
ruijieclient_CFLAGS = -I $(XML_INCLUDE)

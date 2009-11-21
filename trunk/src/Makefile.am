AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = ruijieclient

ruijieclient_CFLAGS = -I $(XML_INCLUDE)


ruijieclient_SOURCES = blog.c codeconv.h myerr.c ruijieclient.h  \
		sendpacket.h blog.h myerr.h codeconv.c ruijieclient.c sendpacket.c \
		 conn_monitor.c conn_monitor.h prase.c prase.h md5.c md5.h \
		 config.c 

ruijieclient_LDADD = $(EXT_LIBS) 
	
if USE_XML 
 ruijieclient_LDADD += -lxml2
endif	 



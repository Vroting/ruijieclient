#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ruijieclient], [0.1.1], [gong@fedoraproject.org])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lnet':
AC_CHECK_LIB([net], [libnet_init libnet_destroy 
libnet_get_hwaddr libnet_get_ipaddr4 
libnet_geterror libnet_write_link])
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [pcap_open_live pcap_fileno 
pcap_close pcap_lookupnet 
pcap_compile pcap_geterr 
pcap_setfilter pcap_freecode
pcap_next_ex])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [MD5_Init MD5_Update MD5_Final])
# FIXME: Replace `main' with a function in `-lxml2':
AC_CHECK_LIB([xml2], [xmlNodeGetContent xmlReadFile xmlDocGetRootElement 
xmlFreeDoc xmlCleanupParser xmlNewDoc xmlNewNode xmlNewProp 
xxmlNewChild mlAddChild xmlDocSetRootElement xmlSaveFormatFileEnc 
xmlMemoryDump])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

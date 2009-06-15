#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ruijieclient], [0.7.9], [gong@fedoraproject.org])

AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

AC_C_BIGENDIAN()

# Checks for library functions.
AC_CHECK_FUNCS([memset strerror])


AC_CHECK_HEADERS([iconv.h linux/rtnetlink.h arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h net/ethernet.h])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main],[],      
            [AC_MSG_FAILURE( libpcap not found!,1)])
            
AC_CHECK_HEADER(pcap.h,[],
			AC_MSG_FAILURE( libpcap development files not found!, 1 ))
			
# important ! here we just determin where the user have got libxml2-devel installed

AC_CHECK_LIB(xml2, [main],[],[AC_WARN(libxml2 not found! xml feature will not work!)])
	
AC_SUBST(XML_INCLUDE,/usr/include/libxml2) 
	
AC_SUBST_FILE(XML_INCLUDE)

# Checks for header files.

AC_ARG_ENABLE(debug,
                [  --enable-debug Enable DEBUG output. This is a debugging feature  which should not be only enabled by develpoers],
                [ CFLAGS="$CFLAGS -g2 -O0 -DDEBUG" ],
                [ CFLAGS="$CFLAGS -g0 -Os"]
              )
             

libpcap=40                
AC_WITH(localpcap,
	AC_SUBST(EXT_LIBS,-L.)
	AC_CONFIG_COMMANDS( libpcap, echo makeing libpcap.so ; (cd src && gcc -lpcap -shared -o  libpcap.so), libpcap=$libpcap)
		  )
		 	
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

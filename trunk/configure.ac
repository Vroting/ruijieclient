#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ruijieclient], [0.1.3], [gong@fedoraproject.org])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strerror])
# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h sys/socket.h unistd.h])

# Checks for header files.
AC_CHECK_HEADERS([sys/ioctl.h net/ethernet.h net/if.h])

AC_ARG_ENABLE(debug,
		[  --enable-debug Enable DEBUG output. This is a debugging feature \
		 which should not be only enabled by develpoers],
		[ CFLAGS=' -g -DDEBUG' ])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main], [],[exit])

# Checks for header files.
AC_CHECK_HEADERS([pcap.h])

# FIXME: Replace `main' with a function in `-lxml2':
AC_CHECK_LIB(xml2, [main], [],
	 [ echo -e "!Warnning: libxml2 not found! xml feature will not work!" ;
	   echo "ruijieclient will continue to work , but will use text file instead" 	   
	])

# Checks for header files.
AC_CHECK_HEADERS([libxml2/libxml/parser.h libxml2/libxml/tree.h])


AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

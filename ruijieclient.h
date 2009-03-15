/*  mystar.h & mystar.c are writton by NetXRay */

#ifndef MYSTAR_H
#define MYSTAR_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include "global.h"

#define FILTER_STR "ether[12:2]=0x888e and ether dst %02x:%02x:%02x:%02x:%02x:%02x"

#define MAX_MSG_LEN 1024
#define MAX_U_MSG_LEN MAX_MSG_LEN*2

#ifdef DEBUG
#define CONF_PATH "ruijie.conf"
#else
#define CONF_PATH "/etc/ruijieclient/ruijie.conf"
#endif

#endif /* MYSTAR_H */

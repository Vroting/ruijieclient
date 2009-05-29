/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun                                          *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 * We just add something to make it more convinence.
 *
 * Many thanks to 'a lonely Wild Goose under the afterglow'(夕霞孤雁)
 *
 * AUTHORS:
 *   Gong Han  <gong AT fedoraproject.org> from CSE@FJNU CN
 *   Chen Tingjun <chentingjun AT gmail.com> from POET@FJNU CN
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Here are some hints regarding conn_monitor's working specifications.
 *
 * (Translated and slightly revised by Gong Han)
 *
 * 1. Basic principle: exert 'ping' to verify availability of gateway
 *    per several seconds. If failed in detecting gateway, namely the
 *    connection has been interrupted, we accordingly restart authentication.
 * 2. The segment of procedure ping is running as a single thread.
 * 3. POSIX thread library(-lpthread) is necessary while Compiling.
 * 4. According to the multithread working environment, we should call 'nanosleep'
 *    by involving it in customised function 'MySleep' instead of
 *    non-thread-safe 'sleep'.
 * 5. Correspondingly replaced 'sleep' in ruijieclient.c with 'MySleep'.
 * 6. We intentionally enabled necessary signal SIGALRM in function
 *    'ConnectionMonitor_init'.
 * 7. One of the reason why we avoid 'sleep' is the conflicts between sleep and
 *    signal SIGALRM.
 * 8. A static variable is added in ruijieclient.c mystar.c that is
 *    'static char  *m_intelligentHost=NULL' and 'static unsigned int m_DbgInfoLevel = 0;'
 *    which specifies detective gateway address.
 * 9. Details about monitoring procedure in pesudocode
 *    Authenticate successfully
 *    ↓
 *    initialise module and pass related parameters:
 *    ConnectionMonitor_init(m_intelligentHost);
 *    ↓
 *    setup detecting gateway interval (SetInterval(2));
 *    ↓
 *    start thread StartConnectionMonitor();
 *    ↓
 *    while (SendEchoPacket(l, pkt_data) == 0)
 *    {
 *      delay;
 *      ↓
 *      determine whether it's able to connect to gateway by IsStillConnected()
 *        if false:
 *           {
 *              stop monitoring StopConnectionMonitor();
 *              restart authentication goto beginAuthentication;
 *           }
 *    }
 *
 *                           composed by 'a lonely Wild Goose under the afterglow'
 *                                                2005.10.20
 */

#ifndef CONN_MONITOR_H
#define CONN_MONITOR_H

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3

int
IsStillConnected(void); /* 判定当前是否联接网络 */
int
StartConnectionMonitor(void); /* 开始监测 */
int
StopConnectionMonitor(void); /* 停止监测 */
int
ConnectionMonitor_init(char * desthost);/*初始化，desthost传入网关或其他可以监测网络联接状态的地址（域名或IP）；dbg_level标识输出调试信息的级别，0为禁止输出调试信息*/
void
SetInterval(unsigned int Interval);/*设置间隔时间*/
void
MySleep(unsigned int Interval);/*替换非线程安全的sleep*/

static void
send_packet(void);
static int
recv_packet(void);

#endif /* CONN_MONITOR_H */

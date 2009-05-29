/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun                                          *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
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

#include "conn_monitor.h"

static char sendpacket[PACKET_SIZE];
static char recvpacket[PACKET_SIZE];
static int sockfd, datalen = 56;
static int nsend = 0, nreceived = 0;
static struct sockaddr_in dest_addr;
static pid_t pid;
static struct sockaddr_in from;

static void
rev_timeout(int signo);
static unsigned short
cal_chksum(unsigned short *addr, int len);
static int
pack(int pack_no);

static int
unpack(char *buf, int len);
static void *
ping_thread(void * arg);
static void
SetConnectionState(int x);
static char *
itoa(long n, int base);

static int is_still_connected = 1; /*标识当前是否联接*/
sem_t Mutex, DbgInfo_Mutex; /*互斥*/
static pthread_t Pinger;
static unsigned int ping_interval = 2;
static int stop_thread_signal = 0;
static unsigned int timeout_count = 0;

//Set the interval of ping
void
SetInterval(unsigned int Interval)
{
  ping_interval = Interval;
}

int
StartConnectionMonitor()
{
  SetConnectionState(1);
  stop_thread_signal = 0;
#ifdef DEBUG
  puts("@@ start connection Monitor");
#endif
}

int
StopConnectionMonitor()
{
  stop_thread_signal = 1;
}

void *
ping_thread(void * arg)
{
  while (1)
    {
#ifdef DEBUG
      printf("@@ ping_thread loop begin:%d\n", pthread_self());
#endif

      if (stop_thread_signal == 1)
        {
          // stop_thread_signal = 0;
#ifdef DEBUG
          puts("@@ Connection_Monitor_thread End");
#endif
        }
      else
        {
          send_packet();
          SetConnectionState(recv_packet());
#ifdef DEBUG
          puts("@@ ping_thread loop end");
#endif
        }
      MySleep(ping_interval); //间隔
    }
}

/* 检测网络联接状态，其间信号量互斥  */
int
IsStillConnected()
{
  int t;
  sem_wait(&Mutex);
  t = is_still_connected;
  sem_post(&Mutex);
  return t;
}

/* 设置网络联接状态，其间信号量互斥  */
void
SetConnectionState(int x)
{
  sem_wait(&Mutex);
  is_still_connected = x;
  sem_post(&Mutex);
}

/* 联接超时 */
void
rev_timeout(int signo)
{
  printf("Timeout (Count:%d)\n", ++timeout_count);
  SetConnectionState(0);

  pthread_exit(NULL);

  // ping_thread(NULL);  //继续线程
}

/*校验和算法*/
unsigned short
cal_chksum(unsigned short *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  /*把ICMP报头二进制数据以2字节为单位累加起来*/
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
  /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

/*设置ICMP报头*/
int
pack(int pack_no)
{
  int i, packsize;
  struct icmp *icmp;
  char * s;
  char st[255];

  icmp = (struct icmp*) sendpacket;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_seq = pack_no;
  icmp->icmp_id = pid;

  packsize = 8 + datalen;
  s = (char *) icmp->icmp_data;
  bzero(s, datalen);

#ifdef DEBUG
  sprintf(st, "## ruijieclient connection test packet NO:%d\n", nsend);
  strcpy(s, st);
  printf("## send packet: %d\n", st);
#endif

  icmp->icmp_cksum = cal_chksum((unsigned short *) icmp, packsize); /*校验算法*/
  return packsize;
}

/*发送ICMP报文*/
void
send_packet()
{
  int packetsize;
  nsend++;
#if DEBUG
  puts("@@ send packet");
#endif
  packetsize = pack(nsend); /*设置ICMP报头*/
  if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *) &dest_addr,
      sizeof(dest_addr)) < 0)
    {
#if DEBUG
      puts("@@ sendto error");
#endif
      return;
    }
#if DEBUG
  puts("@@ Send packet successfully");
#endif
}

/*接收ICMP报文*/
int
recv_packet()
{
  int n, fromlen;
  extern int
  errno;

  if (signal(SIGALRM, rev_timeout) == SIG_ERR)
    err_msg("@@ signal Error");

  alarm(MAX_WAIT_TIME);

  fromlen = sizeof(from);
  RevAgain:
#ifdef DEBUG
  puts("@@ Receive packet");
#endif
  if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
      (struct sockaddr *) &from, &fromlen)) < 0)
    {
#ifdef DEBUG
      printf("@@ recvfrom ErrNO %d\n",itoa(errno));
#endif
      if (errno == EINTR)
        return 0;
      goto RevAgain;
    }
#ifdef DEBUG
  puts("@@ Unpack");
#endif
  if (unpack(recvpacket, n) == 0)
    {
#ifdef DEBUG
      puts("@@ Unpack failed\n");
#endif
      goto RevAgain;
    }
  else
    {
#ifdef DEBUG
      puts("@@ Receive packet successfully");
#endif
      alarm(0);
      return 1;
    }
}

/*剥去ICMP报头*/
int
unpack(char *buf, int len)
{
  int i, iphdrlen;
  struct ip *ip;
  struct icmp *icmp;
  char * s;
  char st[255];

  ip = (struct ip *) buf;
  iphdrlen = ip->ip_hl << 2; /*求ip报头长度,即ip报头的长度标志乘4*/
  icmp = (struct icmp *) (buf + iphdrlen); /*越过ip报头,指向ICMP报头*/
  len -= iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
  if (len < 8) /*小于ICMP报头长度则不合理*/
    {
#ifdef DEBUG
      puts("@@ ICMP packets\'s length is less than 8");
#endif
      return -1;
    }
  /*确保所接收的是我所发的的ICMP的回应*/
  sprintf(st, "MyStar Connection Test Packet NO:%d\n", nsend);
  s = (char *) icmp->icmp_data;
  if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid) && strcmp(
      s, st) == 0)
    {
#ifdef DEBUG
      printf("@@ Get Packet: %s \n", st);
#endif
      return 1;
    }
  else
    {
      if (icmp->icmp_id == pid)
#ifdef DEBUG
        puts("@@ Not My Pack.");
#endif
      return 0;
    }
}

int
OpenAlarmSignal()
{
  sigset_t sigset_alarm;
  sigemptyset(&sigset_alarm);
  if (sigaddset(&sigset_alarm, SIGALRM) == -1)
    return -1;
  if (sigprocmask(SIG_UNBLOCK, &sigset_alarm, NULL) != 0)
    return -1;
  else
    return 0;
}

int
ConnectionMonitor_init(char * desthost)
{
  struct hostent *host;
  struct protoent *protocol;
  int waittime = MAX_WAIT_TIME;
  int size = 50* 1024 ;
  unsigned long int inaddr = 0l;

#ifdef DEBUG
  puts("@@ initialise connection_monitor");
#endif

  if ((protocol = getprotobyname("icmp")) == NULL)
    {
#ifdef DEBUG
      puts("@@ getprotobyname");
#endif
      return 0;
    }

  /*生成使用ICMP的原始套接字,这种套接字只有root才能生成*/
  if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
#ifdef DEBUG
      puts("@@ socket error");
#endif
      return 0;
    }

  /* 回收root权限,设置当前用户权限*/
  setuid(getuid());
  /*扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
   的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答*/
  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  bzero(&dest_addr, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;

  /*判断是主机名还是ip地址*/
#ifdef DEBUG
  printf("## Dest Host: %s\n", desthost);
#endif
  if ((inaddr = inet_addr(desthost)) == INADDR_NONE)
    {
      if ((host = gethostbyname(desthost)) == NULL) /*是主机名*/
        {
          puts("gethostbyname error");
          return 0;
        }
      memcpy((char *) &dest_addr.sin_addr, host->h_addr, host->h_length);
    }
  else /*是ip地址*/
    {
      memcpy((char *) &dest_addr.sin_addr, (char *) &inaddr, sizeof(inaddr));
    }
#ifdef DEBUG
  printf("## Dest Host IP: %s\n", inet_ntoa(dest_addr.sin_addr) );
#endif

  /*获取main的进程id,用于设置ICMP的标志符*/
  pid = getpid();
  OpenAlarmSignal();

  sem_init(&Mutex, 0, 1);
  stop_thread_signal = 1;
  pthread_create(&Pinger, NULL, ping_thread, NULL);

  return 1;
}

void
MySleep(unsigned int Interval)
{
  struct timespec t;
  t.tv_sec = Interval; //暂停Interval秒
  t.tv_nsec = 0; //0纳秒
  nanosleep(&t, NULL);
}

char * itoa(long n, int base)
  /* abs k16 */
{
  register char *p;
  register int minus;
  static char buf[36];

  p = &buf[36];
  *--p = '\0';
  if (n < 0)
    {
      minus = 1;
      n = -n;
    }
  else
    minus = 0;
  if (n == 0)
    *--p = '0';
  else
    while (n > 0)
      {
        *--p = "0123456789abcdef"[n % base];
        n /= base;
      }
  if (minus)
    *--p = '-';
  return p;
}

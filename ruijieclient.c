 /*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun                                          *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 * We just add something to make it more convinence.
 *
 * Many thanks to netxray@byhh
 *
 * AUTHORS:
 *   Gong Han  <gong@fedoraproject.org> from CSE@FJNU CN
 *   Chen Tingjun <chentingjun@gmail.com> from POET@FJNU CN
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
*/

/*
 Mystar is an 802.1x client tool for Linux, which is compatible with MentoSupplicant3.8 for Windows.
 This file contains the main() function of mystar.
 */

#include "ruijieclient.h"
#include "global.h"
#include "sendpacket.h"
#include "myerr.h"
#include "blog.h"
#include "codeconv.h"

/*   Note that: in this file, the global variables (defined without a leading "static")
 from here to the beginning of the definition of main() are referenced by sendpacket.c ( we
 reference them in the form of "extern ..." in sendpacket.c) */

/* These info should be retrieved from mystar.conf */
char *m_name = NULL;//用户名
char *m_password = NULL;//密码
int m_authenticationMode = -1; //是哪种认证模式：0:标准 1:实达
static char *m_nic = NULL;//网卡
static int m_echoInterval = -1; //echo间隔, set to 0 to disable echo
static int m_intelligentReconnect = -1; // 0:don't use it, 1: ues it.  NOTE: not supported NOW!!
static char *m_fakeAddress = NULL; // or set to "123.45.67.89" etc.
static char *m_fakeVersion = NULL; // or set to "3.22" etc.
static char *m_fakeMAC = NULL; // or set to "00:11:D8:44:D5:0D" etc.

/* These information should be worked out by initialization portion. */
unsigned char m_localMAC[6];//本机的MAC地址
unsigned char m_destMAC[6];//服务器的MAC地址.
static unsigned char m_ip[4]; //当前选择的网卡的IP地址
static unsigned char m_netmask[4];//当前选择的网卡的子网掩码
static unsigned char m_netgate[4];//当前选择的网卡的网关
static unsigned char m_dns1[4]; //当前选择的网卡的DNS

/* 当前认证状态
 0:未找到服务器                      1:已找到服务器，未通过用户名认证
 2:已通过用户名认证，未通过MD5认证   3:已通过MD5认证，通网成功         */
static volatile sig_atomic_t m_state = 0;//当前认证状态

ULONG_BYTEARRAY m_serialNo; //序列号,收到第一个有效的Authentication-Success-packet时初始化
ULONG_BYTEARRAY m_key; //密码加密键值,在main()函数开始时初始化

static void
sig_intr(int signo); //do some cleanup work on exit with Ctrl+C
static void
checkAndSetConfig(void); //configure related parameters
static char *
getServMsg(char* msgBuf, size_t msgBufLe, const unsigned char* pkt_data); // get server msg


int
main(int argc, char* argv[])
{
  libnet_t * l = NULL;
  u_int32_t l_ip;
  char l_errbuf[LIBNET_ERRBUF_SIZE];
  struct libnet_ether_addr *l_ether_addr;

  pcap_t *p = NULL;
  int p_fd;
  fd_set read_set;
  char filter_buf[256];
  struct bpf_program filter_code;
  u_int32_t p_netaddr, p_netmask;
  struct pcap_pkthdr *pkt_hdr;
  const unsigned char *pkt_data;
  char p_errbuf[PCAP_ERRBUF_SIZE];

  /* message buffer define*/
  char *pmsgBuf;
  char msgBuf[MAX_MSG_LEN];// orginal msg buf
  char u_msgBuf[MAX_U_MSG_LEN];// utf-8 msg buf.
  //int msgLen;   // orginal msg length
  // note that each utf-8 char takes 4 bytes
  u_int16_t offset;// msg offset

  ULONG_BYTEARRAY uTemp;
  int isFirstPacketFromServer = 1;
  sigset_t sigset_full, sigset_zero;
  struct timespec timeout;
  int packetCount_SentFindServer = 0;
  int packetCount_SentName = 0;
  int packetCount_SentPassword = 0;

  m_serialNo.ulValue = 0x1000002a; //the initial serial number, a magic number!
  checkAndSetConfig();

  if ((l = libnet_init(LIBNET_LINK, m_nic, l_errbuf)) == NULL)
    err_quit("libnet_init: %s\n", l_errbuf);

  if ((p = pcap_open_live(m_nic, 65536, 0, 500, p_errbuf)) == NULL)
    {
      err_msg("pcap_open_live: %s\n", p_errbuf);
      goto err1;
    }
  p_fd = pcap_fileno(p); //we can pselect() it in the following code.

  if ((l_ether_addr = libnet_get_hwaddr(l)) == NULL)
    {
      err_msg("unable to get local mac address :%s\n", libnet_geterror(l));
      goto err2;
    };

  FillFakeMAC(m_fakeMAC, m_localMAC);
  memcpy(m_localMAC, l_ether_addr, sizeof(m_localMAC));

  if (m_fakeAddress == NULL)
    {
      if ((l_ip = libnet_get_ipaddr4(l)) == -1)
        {
          err_msg("unable to get ip address--ingored... :%s\n",
              libnet_geterror(l));
          l_ip = 0;
        }
      memcpy(m_ip, &l_ip, sizeof(m_ip));
    }
  else
    {
    }; //in this case , m_ip has been initialized in checkandSetConfig()

  if (pcap_lookupnet(m_nic, &p_netaddr, &p_netmask, p_errbuf) == -1)
    {
      err_msg("unable to get netmask--igored... %s\n", p_errbuf);
      p_netmask = 0;
    }
  memcpy(m_netmask, &p_netmask, sizeof(m_netmask));

  InitializeBlog(m_ip, m_netmask, m_netgate, m_dns1); //see blog.c and bloc.h for details

  //set the filter. Here I'm sure filter_buf is big enough.
  snprintf(filter_buf, sizeof(filter_buf), FILTER_STR, m_localMAC[0],
      m_localMAC[1], m_localMAC[2], m_localMAC[3], m_localMAC[4],
      m_localMAC[5], m_localMAC[6]);
  if (pcap_compile(p, &filter_code, filter_buf, 0, p_netmask) == -1)
    {
      err_msg("pcap_compile(): %s", pcap_geterr(p));
      goto err2;
    }
  if (pcap_setfilter(p, &filter_code) == -1)
    {
      err_msg("pcap_setfilter(): %s", pcap_geterr(p));
      goto err2;
    }
  pcap_freecode(&filter_code); // avoid  memory-leak

  (void) signal(SIGINT,sig_intr); //We can exit with Ctrl+C
  (void) sigfillset(&sigset_full);
  (void) sigprocmask(SIG_BLOCK,&sigset_full, NULL); //block all signals.

  //search for the server
  beginAuthentication: m_state = 0;
  FillVersion(m_fakeVersion);
  (void) SendFindServerPacket(l); //the first time to search for server
  packetCount_SentFindServer = 1;
  packetCount_SentName = 0;
  packetCount_SentPassword = 0;

  while (1)
    {
      (void) sigfillset(&sigset_full);
      (void) sigdelset(&sigset_full, SIGINT);
      FD_ZERO(&read_set);FD_SET(p_fd, &read_set);
      timeout.tv_sec = 1;
      timeout.tv_nsec = 0; // 1 second

      //wait with all signals(except SIGINT) blocked.
      switch (pselect(p_fd + 1, &read_set, NULL,NULL,&timeout,&sigset_full) )
        {
          case -1: //Normally, this case should not happen since sig_intr() never returns!
          goto err2;
          case 0: //timed out
          switch(m_state)
            {
              case 0:
              if(++packetCount_SentFindServer>3)
                { puts("Restarting authenticaton!"); goto beginAuthentication;}
              (void)SendFindServerPacket(l);
              continue; //jump to next loop of while(1) to receive next packet
          case 1:
          if(++packetCount_SentName>3)
            { puts("Restarting authenticaton!"); goto beginAuthentication;}
          (void)SendNamePacket(l, pkt_data);
          continue;
          case 2:
          if(++packetCount_SentPassword>3)
            { puts("Restarting authenticaton!"); goto beginAuthentication;}
          (void)SendPasswordPacket(l, pkt_data);
          continue;
          default:
          goto err2;
        }
    }

  //Here return value of pselect must be 1

          if((pcap_next_ex(p,&pkt_hdr,&pkt_data))!=1) continue;

          //收到的第二个及其以后的有效packet的源MAC必须等于头次收到的有效分组的源MAC
          if ((!isFirstPacketFromServer)&&(memcmp(m_destMAC,pkt_data+6,6)!=0)) continue;

          //received a packet successfully. for convenience, SUPPOSE it's the RIGHT packet!! but maybe WRONG!!
          //for example, we have NEVER vefified the length of packet, fancying the packet's length is 0x11 ?!

          switch( pkt_data[0x12] ) //分析EAP包类型

            {
              case 0x01: //表示请求
              switch( pkt_data[0x16] )
                {
                  case 0x01: //type 1,以用户名应答
                  if(m_state!=0) continue;
                  m_state=1;
                  fputs("@@ Server found, requesting user name...\n",stdout);
                  if (isFirstPacketFromServer) //获得服务器的MAC地址

                    { memcpy( m_destMAC, pkt_data+6, 6); isFirstPacketFromServer=0;}
                  ++packetCount_SentName;
                  (void)SendNamePacket(l, pkt_data);
                  break;
                  case 0x04: //type 4,挑战，以MD5计算得到的值应答
                  if(m_state!=1) continue;
                  m_state=2;
                  fputs("@@ User name valid, requesting password...\n",stdout);
                  ++packetCount_SentPassword;
                  (void)SendPasswordPacket(l, pkt_data);
                  break;
                }
              break;
              case 0x03: //认证成功
              if(m_state!=2) continue;
              m_state=3;

              pmsgBuf = getServMsg(msgBuf, sizeof(msgBuf), pkt_data);
              if (pmsgBuf == NULL)
                {
                  pmsgBuf = "";
                }
              code_convert(pmsgBuf, strlen(pmsgBuf), u_msgBuf, MAX_U_MSG_LEN);// convert to utf8
              fprintf(stdout,"@@ Password valid, authentication SUCCESS: %s\n",u_msgBuf);

              if (m_echoInterval<=0) goto done; //user has echo disabled

              //uTemp.ulValue = *(((u_long *)(pkt_data+0x9d)));
              offset=ntohs( *((u_int16_t*)(pkt_data+0x10)) );
              uTemp.ulValue = *((u_int32_t *)(pkt_data+(0x11+offset)-0x08));
              m_key.btValue[0] = Alog(uTemp.btValue[3]);
              m_key.btValue[1] = Alog(uTemp.btValue[2]);
              m_key.btValue[2] = Alog(uTemp.btValue[1]);
              m_key.btValue[3] = Alog(uTemp.btValue[0]);

              //unblock SIGINT, so we can exit with Ctrl+C
              (void)sigemptyset(&sigset_zero);
              (void)sigaddset(&sigset_zero,SIGINT);
              (void)sigprocmask(SIG_UNBLOCK,&sigset_zero,NULL);
              // continue echoing
              fputs("Keeping sending echo... \n",stdout);
              while(SendEchoPacket(l,pkt_data)==0) sleep(m_echoInterval);
              goto err2; //this should never happen.

              break;
              case 0x04: //认证失败(用户名或密码错误/不在上网时段内/重复上网等)
              if((m_state==0)||(m_state==3)) continue;
              m_state=0;
              pmsgBuf = getServMsg(msgBuf, sizeof(msgBuf), pkt_data);
              if (pmsgBuf == NULL)
                {
                  pmsgBuf = "";
                }
              code_convert(pmsgBuf, strlen(pmsgBuf), u_msgBuf, MAX_U_MSG_LEN);// convert to utf8
              fprintf(stdout,"@@ Authenticaton failed: %s\n",u_msgBuf);
              (void)SendEndCertPacket(l);

              goto beginAuthentication;

              break; //should never come here

            }// end switch
        }// end while

      done:
      pcap_close(p); libnet_destroy(l);
      return 0;

      err2:
      pcap_close(p);
      err1:
      libnet_destroy(l);
      return 1;
    }

static char *
getServMsg(char* msgBuf, size_t msgBufLen, const unsigned char* pkt_data)
{

  /* message buffer define*/
  int msgLen; // orginal msg length

  msgLen = ntohs(*((u_int16_t*) (pkt_data + 0x10))) - 10;
  if (msgLen > 0)
    {
      if (msgLen >= (msgBufLen - 1))
        msgLen = msgBufLen - 1;
      memset(msgBuf, '\0', msgBufLen);
      memcpy(msgBuf, pkt_data + 0x1c, msgLen);
      //remove the leanding "\r\n" which seems alway to exist!
#ifdef DEBUG
      puts("-- MSG INFO");
      printf("## msgBuf(GB) %s\n", msgBuf);
#endif
      if ((msgLen > 2) && (msgBuf[0] == 0xd) && (msgBuf[1] == 0xa))
        {
#ifdef DEBUG
          puts("@@ /r/n found");
          puts("-- END");
#endif
          return msgBuf + 0x02;
        }
      else
        {
#ifdef DEBUG
          puts("@@ /r/n not found");
          puts("-- END");
#endif
          return msgBuf;
        }
    }
  else
    {
      return NULL;
    } //这个估计是服务器告知静默或确认断网的包
}

static void
checkAndSetConfig(void)
{
  FILE *fp;
  char buf[4096];
  char *p;
  int i, len;
  static char name[32];
  static char password[32];
  static char nic[32];
  static char fakeAddress[32];
  static char fakeVersion[8];
  static char fakeMAC[32];

  int intelligentReconnect = -1;
  int echoInterval = -1;
  int authenticationMode = -1;

  //the check and anylysis against ruijie.conf  *don't*  work perfectly.
  //this may be improved in the later version.
  if ((fp = fopen(CONF_PATH,"r")) == NULL)
    err_quit("cannot open file ruijie.conf ! check it.\n");

  while (fgets(buf, sizeof(buf), fp) != NULL)
    {
      if ((buf[0] == '#') || (buf[0] == '\n'))
        continue;
      len = strlen(buf);
      if (buf[len - 1] == '\n')
        buf[len - 1] = '\0';
      if (((p = strchr(buf, '=')) == NULL) || (p == buf))
        continue;
      //the code above doesn't detect ALL the errors!! it should be improved in future.

      *p++ = '\0';
      for (i = 0; i < strlen(buf); i++)
        buf[i] = tolower(buf[i]);

      puts(buf);
      if (strcmp(buf, "name") == 0)
        {
          strncpy(name, p, sizeof(name) - 1);
          name[sizeof(name) - 1] = 0;
          m_name = name;
        }
      else if (strcmp(buf, "password") == 0)
        {
          strncpy(password, p, sizeof(password) - 1);
          password[sizeof(password) - 1] = 0;
          m_password = password;
        }
      else if (strcmp(buf, "authenticationmode") == 0)
        {
          authenticationMode = atoi(p);
          m_authenticationMode = authenticationMode;
        }
      else if (strcmp(buf, "nic") == 0)
        {
          for (i = 0; i < strlen(p); i++)
            p[i] = tolower(p[i]);
          strncpy(nic, p, sizeof(nic) - 1);
          nic[sizeof(nic) - 1] = 0;
          m_nic = nic;
        }
      else if (strcmp(buf, "echointerval") == 0)
        {
          echoInterval = atoi(p);
          m_echoInterval = echoInterval;
        }
      else if (strcmp(buf, "intelligentreconnect") == 0)
        {
          intelligentReconnect = atoi(p);
          m_intelligentReconnect = intelligentReconnect;
        }
      else if (strcmp(buf, "fakeversion") == 0)
        {
          strncpy(fakeVersion, p, sizeof(fakeVersion) - 1);
          fakeVersion[sizeof(fakeVersion) - 1] = 0;
          m_fakeVersion = fakeVersion;
        }
      else if (strcmp(buf, "fakemac") == 0)
        {
          strncpy(fakeMAC, p, sizeof(fakeMAC) - 1);
          fakeMAC[sizeof(fakeMAC) - 1] = 0;
          m_fakeMAC = fakeMAC;
        }
      else if (strcmp(buf, "fakeaddress") == 0)
        {
          strncpy(fakeAddress, p, sizeof(fakeAddress) - 1);
          fakeAddress[sizeof(fakeAddress) - 1] = 0;
          if (inet_pton(AF_INET,fakeAddress, m_ip) <= 0)
            err_msg("invalid fakeAddress found in ruijie.conf, ignored...\n");
          else
            m_fakeAddress = fakeAddress;
        }
      else
        continue;
    }
  if (ferror(fp))
    err_quit("cannot read ruijie.conf ! check it.\n");
  fclose(fp);

  if ((m_name == NULL) || (m_name[0] == 0))
    err_quit("invalid name found in ruijie.conf!\n");
  if ((m_password == NULL) || (m_password[0] == 0))
    err_quit("invalid password found in ruijie.conf!\n");
  if ((m_authenticationMode < 0) || (m_authenticationMode > 1))
    err_quit("invalid authenticationMode found in ruijie.conf!\n");
  if ((m_nic == NULL) || (strcmp(m_nic, "") == 0)
      || (strcmp(m_nic, "any") == 0))
    err_quit("invalid nic found in ruijie.conf!\n");
  if ((m_echoInterval < 0) || (m_echoInterval > 100))
    err_quit("invalid echo interval found in ruijie.conf!\n");
  if ((m_intelligentReconnect < 0) || (m_intelligentReconnect > 1))
    err_quit("invalid intelligentReconnect found in ruijie.conf!\n");

#ifdef DEBUG
  puts("-- CONF INFO");
  printf("## m_name=%s\n", m_name);
  printf("## m_password=%s\n", m_password);
  printf("## m_nic=%s\n", m_nic);
  printf("## m_authenticationMode=%d\n", m_authenticationMode);
  printf("## m_echoInterval=%d\n", m_echoInterval);
  printf("## m_intelligentReconnect=%d\n", m_intelligentReconnect);//NOT supported now!!
  printf("## m_fakeVersion=%s\n", m_fakeVersion);
  printf("## m_fakeAddress=%s\n", m_fakeAddress);
  printf("## m_fakeMAC=%s\n", m_fakeMAC);
  puts("-- END");
#endif

  memset(m_netgate, 0, sizeof(m_netgate));
  memset(m_dns1, 0, sizeof(m_dns1));
}

static void
sig_intr(int signo)
{
  libnet_t *l = NULL;
  char l_errbuf[LIBNET_ERRBUF_SIZE];

  if (m_state == 3)
    {
      if ((l = libnet_init(LIBNET_LINK, m_nic, l_errbuf)) == NULL)
        _exit(0);
      (void) SendEndCertPacket(l);
      libnet_destroy(l);
    }
  _exit(0);
}


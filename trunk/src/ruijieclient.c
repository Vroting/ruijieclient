/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun                                          *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 *
 * Many thanks to netxray@byhh, 'a lonely Wild Goose under the afterglow'(夕霞孤雁)
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "ruijieclient.h"
#include "global.h"
#include "sendpacket.h"
#include "myerr.h"
#include "blog.h"
#include "codeconv.h"
#include "conn_monitor.h"

/*   Note that: in this file, the global variables (defined without a leading "static")
 from here to the beginning of the definition of main() are referenced by sendpacket.c ( we
 reference them in the form of "extern ..." in sendpacket.c) */

/* These info should be retrieved from ruijie.conf */

// auth mode: 0:standard 1:Star private
int m_authenticationMode = -1;
// indicator of adapter
static char *m_nic = NULL;
// echo interval, 0 means disable echo
static int m_echoInterval = -1;
// Intelligent Reconnect 0:disable, 1: enable.
static int m_intelligentReconnect = -1;
// fake ip, e.g. "123.45.67.89"
static char *m_fakeAddress = NULL;
// fake version, e.g. "3.22"
static char *m_fakeVersion = NULL;
// fake MAC, e.g. "00:11:D8:44:D5:0D"
static char *m_fakeMAC = NULL;
// detective gateway address
static char m_intelligentHost[16] = "4.2.2.2";

// flag of afterward DHCP status
int noip_afterauth=1;

// user name
static char name[32];
// password
static char password[32];
static char nic[32];
static char fakeAddress[32];
static char fakeVersion[8];
static char fakeMAC[32];


/* These info should be worked out by initialisation portion. */

/* Authenticate Status
 * 0: fail to find server
 * 1: fail to pass Authentication of user name
 * 2: fail to pass Authentication of MD5 sum
 * 3: success
*/
static volatile sig_atomic_t m_state = 0;

/* cleanup on exit when detected Ctrl+C */
static void
logoff(int signo);
#if defined(LIBXML_TREE_ENABLED) && defined(LIBXML_OUTPUT_ENABLED)
/* configure related parameters */
static void
checkAndSetConfig(void);
/* generate default setting file */
static int
GenSetting(void);
static void
get_element(xmlNode * a_node);
#endif
/* get server msg */
static char *
getServMsg(char* msgBuf, size_t msgBufLe, const unsigned char* pkt_data);
/* kill other processes */
static void
kill_all(char* process);

////最最最重要的啊，消灭全局变量全靠这个家伙的啊
ruijie_packet sender={0};
int
main(int argc, char* argv[])
{

  fd_set read_set;
  char filter_buf[256];
  struct bpf_program filter_code;
  struct pcap_pkthdr *pkt_hdr;
  const unsigned char *pkt_data;
  char p_errbuf[PCAP_ERRBUF_SIZE];

  /* message buffer define*/
  char *pmsgBuf;
  // original msg buf
  char msgBuf[MAX_MSG_LEN];
  // utf-8 msg buf. note that each utf-8 character takes 4 bytes
  char u_msgBuf[MAX_U_MSG_LEN];
  // msg offset
  u_int16_t offset;
  // system command
  char cmd[32] = "dhclient ";

  ULONG_BYTEARRAY uTemp;
  int isFirstPacketFromServer = 1;
  sigset_t sigset_full, sigset_zero;
  struct timespec timeout;
  int packetCount_SentFindServer = 0;
  int packetCount_SentName = 0;
  int packetCount_SentPassword = 0;

  // the initial serial number, a magic number!
  sender.m_serialNo.ulValue = 0x1000002a;

  // kill all other ruijieclients which are running
  kill_all("ruijieclient");
  kill_all("xgrsu 2> /dev/null");

  // if '-g' is passed as argument then generate a sample configuration
  if (argc>1 && strcmp(argv[1], "g"))
    {
      GenSetting();
      exit(EXIT_SUCCESS);
    }

  checkAndSetConfig();

  strcat(cmd, m_nic);

  if (sender.m_dhcpmode > 0)
	{
		// kill all other dhclients which are running
		kill_all("dhclient");
	}


  if ((sender.m_pcap  = pcap_open_live(m_nic, 65536, 0, 500, p_errbuf)) == NULL)
    {
      err_msg("pcap_open_live: %s\n", p_errbuf);

      return 1;
    }
  sender.m_pcap_no = pcap_fileno(sender.m_pcap); // we can poll() it in the following code.

  {
		struct ifreq rif={{{0}}};

		// 获得选定的网卡地址。
		strcpy(rif.ifr_name,m_nic);
		int tmp = socket(AF_INET, SOCK_DGRAM, 0);

		if (m_fakeAddress == NULL)
		{
			ioctl(tmp, SIOCGIFADDR, &rif);
			memcpy(&(sender.m_ip), rif.ifr_addr.sa_data+2, 4);
//			struct in_addr p;
//			p.s_addr = sender.m_ip;
//			printf("ip is %s",inet_ntoa(p));
		}
		// else m_ip has been initialized in checkandSetConfig()

		ioctl(tmp, SIOCGIFNETMASK, &rif);

		memcpy(&(sender.m_mask),rif.ifr_addr.sa_data +2 ,4);
//		{
//			struct in_addr p;
//			p.s_addr = sender.m_mask;
//			printf("mask is %s",inet_ntoa(p));
//		}

		ioctl(tmp, SIOCGIFHWADDR, &rif);
		memcpy(sender.m_ETHHDR+ETHER_ADDR_LEN,rif.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
		close(tmp);
  }

  // check blog.c and bloc.h for details
  InitializeBlog(&sender);

  // set the filter. Here I'm sure filter_buf is big enough.
  snprintf(filter_buf, sizeof(filter_buf), FILTER_STR,
      sender.m_ETHHDR[6], sender.m_ETHHDR[7], sender.m_ETHHDR[8],
      sender.m_ETHHDR[9], sender.m_ETHHDR[10], sender.m_ETHHDR[11]);

  if (pcap_compile(sender.m_pcap, &filter_code, filter_buf, 0, sender.m_mask) == -1)
    {
      err_msg("pcap_compile(): %s", pcap_geterr(sender.m_pcap));
      pcap_close(sender.m_pcap);
      return 1;
    }
  if (pcap_setfilter(sender.m_pcap, &filter_code) == -1)
    {
      err_msg("pcap_setfilter(): %s", pcap_geterr(sender.m_pcap));
      pcap_close(sender.m_pcap);
      return 1;
    }
  pcap_freecode(&filter_code); // avoid  memory-leak

  signal(SIGHUP, logoff);
  signal(SIGINT, logoff);
  signal(SIGQUIT, logoff);
  signal(SIGABRT, logoff);
  signal(SIGKILL, logoff);
  signal(SIGTERM, logoff);
  signal(SIGSTOP, logoff);
  signal(SIGTSTP, logoff);

  sigfillset(&sigset_full);
  sigprocmask(SIG_BLOCK, &sigset_full, NULL); // block all signals.

  // search for the server
beginAuthentication:
  m_state = 0;
  FillVersion(m_fakeVersion); // fill 2 bytes with fake version

  /* comment out for futher usage
  if (m_fakeMAC != NULL)
    {
      //fill m_localMAC with a fake MAC address
      FillFakeMAC(m_localMAC, m_fakeMAC);
    }
   */
  SendFindServerPacket(&sender); // the first time to search for server
  packetCount_SentFindServer = 1;
  packetCount_SentName = 0;
  packetCount_SentPassword = 0;

  while (1)
    {
      sigfillset(&sigset_full);
      sigdelset(&sigset_full, SIGHUP);
      sigdelset(&sigset_full, SIGINT);
      sigdelset(&sigset_full, SIGQUIT);
      sigdelset(&sigset_full, SIGABRT);
      sigdelset(&sigset_full, SIGKILL);
      sigdelset(&sigset_full, SIGTERM);
      sigdelset(&sigset_full, SIGSTOP);
      sigdelset(&sigset_full, SIGTSTP);

      FD_ZERO(&read_set);
      FD_SET(sender.m_pcap_no, &read_set);
      timeout.tv_sec = 1;
      timeout.tv_nsec = 0; // 1 second

      // wait with all signals(except SIGINT SIGQUIT SIGSTOP) blocked.
      switch (pselect( sender.m_pcap_no +1, &read_set, NULL,
          NULL, &timeout, &sigset_full) )
        {
        case -1: // Normally, this case should not happen since sig_intr() never returns!
          pcap_close(sender.m_pcap);

          return 1;
        case 0: // timed out
          switch(m_state)
            {
            case 0:
              if(++packetCount_SentFindServer > 3)
              {
                puts("Restarting authentication!");
                goto beginAuthentication;
              }
              SendFindServerPacket(&sender);
              continue; // jump to next loop of while(1) to receive next packet
            case 1:
              if(++packetCount_SentName > 3)
              {
                puts("Restarting authentication!");
                goto beginAuthentication;
              }
              SendNamePacket(&sender, pkt_data);
              continue;
            case 2:
              if(++packetCount_SentPassword > 3)
              {
                puts("Restarting authentication!");
                goto beginAuthentication;
              }
              SendPasswordPacket(&sender, pkt_data);
              continue;
            default:
              pcap_close(sender.m_pcap);
              return 1;
            }
        }

      // Here return value of pselect() must be 1

      if((pcap_next_ex(sender.m_pcap,&pkt_hdr, &pkt_data)) != 1)
        continue;

      /* source MAC of the second and the following valid packets should be identical
       * to the source MAC of first valid server finding packet
       */
      if ((!isFirstPacketFromServer) && (memcmp(sender.m_ETHHDR,pkt_data+6, 6) != 0))
        continue;

      /* received a packet successfully. for convenience, SUPPOSE it's the RIGHT packet!!
       * but maybe WRONG!! for example, we have NEVER verified the length of packet,
       * fancying the packet's length is 0x11 ?!
       */

      switch( pkt_data[0x12] ) // analysis EAP packet type
        {
        case 0x01: // means request
          switch(pkt_data[0x16])
            {
            case 0x01:
            // type 1, response with username
              if (m_state != 0)
                continue;
              m_state = 1;
              fputs("@@ Server found, requesting user name...\n", stdout);
              if (isFirstPacketFromServer)
              {
                // get server's MAC address.
                memcpy( sender.m_ETHHDR, pkt_data+6, 6);
                isFirstPacketFromServer = 0;
              }
              ++packetCount_SentName;

              /* comment out for further usage
              if (m_fakeMAC != NULL)
                {
                  //fill m_localMAC with a fake MAC address
                  FillFakeMAC(m_localMAC, m_fakeMAC);
                }
                */
              SendNamePacket(&sender, pkt_data);
              break;
            case 0x04:
              // type 4, Challenge，response with the returned by MD5 algorithm
              if(m_state != 1)
                continue;
              m_state = 2;
              fputs("@@ User name valid, requesting password...\n", stdout);
              ++packetCount_SentPassword;
              SendPasswordPacket(&sender, pkt_data);
              break;
            }
          break;
        case 0x03:
          // Authenticate successfully
          if(m_state != 2)
            continue;

          if(sender.m_dhcpmode == 2 && noip_afterauth){
              if (system(cmd) == -1)
                {
                  err_quit("Fail in retrieving network configuration from DHCP server");
                }
              noip_afterauth = 0;
          }

          m_state=3;

          pmsgBuf = getServMsg(msgBuf, sizeof(msgBuf), pkt_data);
          if (pmsgBuf == NULL)
            {
              // if pmsgBuf doesn't exist.
              pmsgBuf = "";
            }
          // convert to utf8
          code_convert(u_msgBuf, MAX_U_MSG_LEN, pmsgBuf, strlen(pmsgBuf));
          fprintf(stdout,
              "@@ Password valid, SUCCESS:\n## Server Message: %s\n",
              u_msgBuf);

          if (m_echoInterval <= 0) {
            pcap_close(sender.m_pcap);
            return 0; //user has echo disabled
          }

          //uTemp.ulValue = *(((u_long *)(pkt_data+0x9d)));
          offset = ntohs( *((u_int16_t*)(pkt_data+0x10)) );
          uTemp.ulValue = *((u_int32_t *)(pkt_data+(0x11+offset)-0x08));
          sender.m_key.btValue[0] = Alog(uTemp.btValue[3]);
          sender.m_key.btValue[1] = Alog(uTemp.btValue[2]);
          sender.m_key.btValue[2] = Alog(uTemp.btValue[1]);
          sender.m_key.btValue[3] = Alog(uTemp.btValue[0]);

          // unblock SIGINT SIGSTOP SIGQUIT, so we can exit with Ctrl+C
          sigemptyset(&sigset_zero);
          sigaddset(&sigset_zero, SIGHUP);
          sigaddset(&sigset_zero, SIGINT);
          sigaddset(&sigset_zero, SIGQUIT);
          sigaddset(&sigset_zero, SIGABRT);
          sigaddset(&sigset_zero, SIGABRT);
          sigaddset(&sigset_zero, SIGKILL);
          sigaddset(&sigset_zero, SIGTERM);
          sigaddset(&sigset_zero, SIGSTOP);
          sigaddset(&sigset_zero, SIGTSTP);
          sigprocmask(SIG_UNBLOCK, &sigset_zero, NULL);
          // continue echoing
          fputs("Keeping sending echo...\nPress Ctrl+C to logoff \n", stdout);
          // start ping monitoring
          if (m_intelligentReconnect == 1)
          {

              while (SendEchoPacket(&sender, pkt_data) == 0)
              {
            	  // TODO: put code here
            	  sleep(m_echoInterval);
              }
          }
          if (m_intelligentReconnect > 10)
          {
        	  time_t time_recon = time(NULL);
        	  while (1){
        		  long time_count = time(NULL)-time_recon ;
        		  if (time_count >=  m_intelligentReconnect){
            	  fputs("Time to reconect!\n",stdout);
            	  goto beginAuthentication;
              }
              sleep(m_echoInterval);
          }
          }
          pcap_close(sender.m_pcap);
          return 1; // this should never happen.

          break;
        case 0x04:
          /* authenticate fail
           * possible reasons:
           * 1. user name and password mismatch
           * 2. not in the right time-period of net accessing
           * 3. account has been logged at other computers
           */
          if((m_state == 0) || (m_state == 3))
            continue;
          m_state=0;
          pmsgBuf = getServMsg(msgBuf, sizeof(msgBuf), pkt_data);
          if (pmsgBuf == NULL)
            {
              // if pmsgBuf doesn't exist.
              pmsgBuf = "";
            }
          // convert to utf8
          code_convert(u_msgBuf, MAX_U_MSG_LEN, pmsgBuf, strlen(pmsgBuf));
          fprintf(stdout,"@@ Authentication failed: %s\n",u_msgBuf);
          SendEndCertPacket(&sender);
          goto beginAuthentication;
          break; // should never come here
        }// end switch
    }// end while
}

static char *
getServMsg(char* msgBuf, size_t msgBufLen, const unsigned char* pkt_data)
{

  /* message buffer define*/
  int msgLen; // original msg length

  msgLen = ntohs(*((u_int16_t*) (pkt_data + 0x10))) - 10;
  if (msgLen > 0)
    {
      if (msgLen >= (msgBufLen - 1))
        msgLen = msgBufLen - 1;
      memset(msgBuf, '\0', msgBufLen);
      memcpy(msgBuf, pkt_data + 0x1c, msgLen);
      //remove the leading "\r\n" which seems always exist!
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
    } // this presumably is packet indicates silent or interrupt network
}

#ifdef LIBXML_TREE_ENABLED

static void
get_element(xmlNode * a_node)
  {
    xmlNode *cur_node = NULL;
    char *node_content, *node_name;
    int i ;

    for (cur_node = a_node; cur_node != NULL; cur_node = cur_node->next)
      {
        node_content = (char *)xmlNodeGetContent(cur_node);
        node_name = (char *)(cur_node->name);
        if (cur_node->type == XML_ELEMENT_NODE &&
            strcmp(node_content, "") &&
            node_name != NULL
            )
          {
            if (strcmp(node_name, "Name") == 0)
              {
                strncpy(name, node_content, sizeof(name) - 1);
                name[sizeof(name) - 1] = 0;
                sender.m_name = name;
              }
            else if (strcmp(node_name, "Password") == 0)
              {
                strncpy(password, node_content, sizeof(password) - 1);
                password[sizeof(password) - 1] = 0;
                sender.m_password = password;
              }
            else if (strcmp(node_name, "AuthenticationMode") == 0)
              {
                m_authenticationMode = atoi(node_content);
              }
            else if (strcmp(node_name, "NIC") == 0)
              {
                for (i = 0; i < strlen(node_content); i++)
                  node_content[i] = tolower(node_content[i]);
                strncpy(nic, node_content, sizeof(nic) - 1);
                nic[sizeof(nic) - 1] = 0;
                m_nic = nic;
              }
            else if (strcmp(node_name, "EchoInterval") == 0)
              {
                m_echoInterval = atoi(node_content);
              }
            else if (strcmp(node_name, "IntelligentReconnect") == 0)
              {
                m_intelligentReconnect = atoi(node_content);
              }
            else if (strcmp(node_name, "FakeVersion") == 0)
              {
                strncpy(fakeVersion, node_content, sizeof(fakeVersion) - 1);
                fakeVersion[sizeof(fakeVersion) - 1] = 0;
                m_fakeVersion = fakeVersion;
              }
            else if (strcmp(node_name, "DHCPmode") == 0)
              {
                sender.m_dhcpmode = atoi(node_content);
              }
             /* comment out for further useage
            else if (strcmp(node_name, "FakeMAC") == 0)
              {
                strncpy(fakeMAC, node_content, sizeof(fakeMAC) - 1);
                fakeMAC[sizeof(fakeMAC) - 1] = 0;
                m_fakeMAC = fakeMAC;
              }
              */
            else if (strcmp(node_name, "FakeAddress") == 0)
              {
                strncpy(fakeAddress, node_content, sizeof(fakeAddress) - 1);
                fakeAddress[sizeof(fakeAddress) - 1] = 0;
                if (inet_pton(AF_INET, fakeAddress, & sender.m_ip) <= 0)
                err_msg("invalid fakeAddress found in ruijie.conf, ignored...\n");
                else
                m_fakeAddress = fakeAddress;
              }
          }

        get_element(cur_node->children);
      }
  }

static void
checkAndSetConfig(void)
  {

    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
    doc = xmlReadFile(CONF_PATH, NULL, 0);

    if (doc == NULL)
      {
        puts("Could not parse or find file. A sample file will be generated "
            "automatically. Try 'gedit /etc/ruijie.conf'");
        if (GenSetting() != -1)
          {
            puts("Configuration file has been generated.");
            exit(0);
          }
        else
          {
            err_quit("Configuration file fail in generating.");
          }

      }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    get_element(root_element);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    if ((sender.m_name == NULL) || (sender.m_name[0] == 0))
    err_quit("invalid name found in ruijie.conf!\n");
    if ((sender.m_password == NULL) || (sender.m_password[0] == 0))
    err_quit("invalid password found in ruijie.conf!\n");
    if ((m_authenticationMode < 0) || (m_authenticationMode> 1))
    err_quit("invalid authenticationMode found in ruijie.conf!\n");
    if ((m_nic == NULL) || (strcmp(m_nic, "") == 0)
        || (strcmp(m_nic, "any") == 0))
    err_quit("invalid nic found in ruijie.conf!\n");
    if ((m_echoInterval < 0) || (m_echoInterval> 100))
    err_quit("invalid echo interval found in ruijie.conf!\n");
    //if ((m_intelligentReconnect < 0) || (m_intelligentReconnect> 1))
    if ((m_intelligentReconnect < 0))
    err_quit("invalid intelligentReconnect found in ruijie.conf!\n");

#ifdef DEBUG
    puts("-- CONF INFO");
    printf("## m_name=%s\n", m_name);
    printf("## m_password=%s\n", m_password);
    printf("## m_nic=%s\n", m_nic);
    printf("## m_authenticationMode=%d\n", m_authenticationMode);
    printf("## m_echoInterval=%d\n", m_echoInterval);
    printf("## m_intelligentReconnect=%d\n", m_intelligentReconnect);// NOT supported now!!
    printf("## m_fakeVersion=%s\n", m_fakeVersion);
    printf("## m_fakeAddress=%s\n", m_fakeAddress);
    printf("## m_fakeMAC=%s\n", m_fakeMAC);
    puts("-- END");
#endif

  }

static int
GenSetting(void)
  {

    xmlDocPtr doc = NULL; /* document pointer */

    xmlNodePtr root_node = NULL, account_node = NULL,
    setting_node = NULL;//, msg_node = NULL;/* node pointers */

    int rc;

    // Creates a new document, a node and set it as a root node

    doc = xmlNewDoc(BAD_CAST "1.0");

    root_node = xmlNewNode(NULL, BAD_CAST CONF_NAME);
    xmlNewProp(root_node, BAD_CAST "version", BAD_CAST C_VERSION);
    xmlAddChild(root_node, xmlNewComment((xmlChar *)
            "This is a sample configuration file of RuijieClient, "
            "change it appropriately according to your settings."));

    xmlDocSetRootElement(doc, root_node);

    //creates a new node, which is "attached" as child node of root_node node.
    account_node = xmlNewChild(root_node, NULL, BAD_CAST "account", NULL);
    xmlNewChild(account_node, NULL, BAD_CAST "Name", BAD_CAST "");
    xmlNewChild(account_node, NULL, BAD_CAST "Password", BAD_CAST "");

    setting_node = xmlNewChild(root_node, NULL, BAD_CAST "settings", NULL);
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "0: Standard, 1: Private"));
    xmlNewChild(setting_node, NULL, BAD_CAST "AuthenticationMode", BAD_CAST "1");
    xmlNewChild(setting_node, NULL, BAD_CAST "NIC", BAD_CAST "eth0");
    xmlNewChild(setting_node, NULL, BAD_CAST "EchoInterval", BAD_CAST "25");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "IntelligentReconnect: "
        "0: Disable IntelligentReconnect, 1: Enable IntelligentReconnect "));
    xmlNewChild(setting_node, NULL, BAD_CAST "IntelligentReconnect", BAD_CAST "1");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "AutoConnect: "
        "0: Disable AutoConnect, 1: Enable AutoConnect (only available in"
        " gruijieclient) "));
    xmlNewChild(setting_node, NULL, BAD_CAST "AutoConnect", BAD_CAST "0");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "Fake Version for cheating server"));
    xmlNewChild(setting_node, NULL, BAD_CAST "FakeVersion", BAD_CAST "3.99");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "Fake IP for cheating server"));
    xmlNewChild(setting_node, NULL, BAD_CAST "FakeAddress", BAD_CAST "");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "DHCP mode 0: Disable, "
        "1: Enable DHCP before authentication, 2: Enable DHCP after authentication "));
    xmlNewChild(setting_node, NULL, BAD_CAST "DHCPmode", BAD_CAST "0");

    //Dumping document to stdio or file
    rc = xmlSaveFormatFileEnc(CONF_PATH, doc, "UTF-8", 1);

    if (rc == -1)
      return -1;
    /*free the document */

    xmlFreeDoc(doc);

    xmlCleanupParser();

    xmlMemoryDump(); // debug memory for regression tests

    return 0;
  }
#endif

static void
logoff(int signo)
{
  if (m_state == 3)
    {
      SendEndCertPacket(&sender);
    }
  _exit(0);
}

static void
kill_all(char * process)
{
	  char cmd[256] = "";
	  int cmd_return = 0 ;

	  sprintf(cmd, "killall --signal 2 %s", process);
	  cmd_return = system(cmd);
	  if ( cmd_return < 0) {
		  err_sys("Killall Failure !") ;
	  }
}

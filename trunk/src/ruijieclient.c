/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun  Microcai                                *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 *
 * Many thanks to netxray@byhh
 *
 * AUTHORS:
 *   Gong Han  <gong AT fedoraproject.org> from CSE@FJNU CN
 *   Chen Tingjun <chentingjun AT gmail.com> from POET@FJNU CN
 *   microcai <microcai AT sina.com > from ZSTU
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
#include <unistd.h>
#include <net/if.h>
#include "ruijieclient.h"
#include "global.h"
#include "sendpacket.h"
#include "myerr.h"
#include "blog.h"
#include "conn_monitor.h"
#include "prase.h"
/*   Note that: in this file, the global variables (defined without a leading "static")
 from here to the beginning of the definition of main() are referenced by sendpacket.c ( we
 reference them in the form of "extern ..." in sendpacket.c) */

/* These info should be retrieved from ruijie.conf */

// indicator of adapter
static char *m_nic = NULL;
// echo interval, 0 means disable echo
static int m_echoInterval = 0;
// Intelligent Reconnect 0:disable, 1: enable.
static int m_intelligentReconnect = 0;
// fake ip, e.g. "123.45.67.89"
static char *m_fakeAddress = NULL;
// fake version, e.g. "3.22"
static char *m_fakeVersion = NULL;
// fake MAC, e.g. "00:11:D8:44:D5:0D"
static char *m_fakeMAC = NULL;
// detective gateway address
static char m_intelligentHost[16] = "4.2.2.2";

// flag of afterward DHCP status
int noip_afterauth = 1;

// user name
static char name[32]={0};
// password
static char password[32]={0};
static char nic[32];
static char fakeAddress[32];
static char fakeVersion[8];
static char fakeMAC[32];
static char config_file[256]=CONF_PATH;
/* These info should be worked out by initialisation portion. */

/* Authenticate Status
 * 0: fail to find server
 * 1: fail to pass Authentication of user name
 * 2: fail to pass Authentication of MD5 sum
 * 3: success
 */

/* cleanup on exit when detected Ctrl+C */
static void
logoff(int signo);

/*Check whether we have got enough configuration info*/
static void
CheckConfig();

#if defined(LIBXML_TREE_ENABLED) && defined(LIBXML_OUTPUT_ENABLED)
/* configure related parameters */
static void
GetConfig();
/* generate default setting file */
static int
GenSetting(void);
static void
get_element(xmlNode * a_node);
#endif

/* kill other processes */
static int
kill_all(char* process);

// this is a top crucial change that eliminated all global variables
ruijie_packet sender =   { 0 };
int
main(int argc, char* argv[])
{
  fd_set read_set;
  char filter_buf[256];
  struct bpf_program filter_code;

  char p_errbuf[PCAP_ERRBUF_SIZE];

  /* message buffer define*/
  // utf-8 msg buf. note that each utf-8 character takes 4 bytes
  char u_msgBuf[MAX_U_MSG_LEN];

  // system command
  char cmd[32] = "dhclient -4"; //ipv4 only

  long setdaemon=0;
  long genfile=0;
  long nocfg=0;
  long kill_ruijieclient=0;
  struct parameter_tags param[] =
  {
  		{"-D", (char*)&setdaemon,0,sizeof(setdaemon),2, BOOL_both},
  		{"--daemon", (char*)&setdaemon,"-D,--daemon\trun as a daemon",sizeof(setdaemon),8, BOOL_both},
  		{"-n", nic ,0,sizeof(nic),2, STRING},
  		{"--nic", nic ,"-n,--nic\tnet card",sizeof(nic),5, STRING},
  		{"-g", (char*)&genfile ,"-g\t\tauto generate a sample configuration",sizeof(genfile),2, BOOL_both},
  		{"--noconfig",(char*)&nocfg,"--noconfig\tdo not read config from file",sizeof(nocfg),10,BOOL_both},
  		{"-f",config_file,0,sizeof(config_file),2,STRING},
  		{"--config",config_file,"-f,--config\tsupply alternative config file",sizeof(config_file),8,STRING},
  		{"-u",name ,0,sizeof(name),2,STRING},
  		{"--user",name,"-u,--user\tsupply username",sizeof(name),6,STRING},
  		{"-p",password ,0,sizeof(password),2,STRING},
  		{"--passwd",password,"-p,--passwd\tsupply password",sizeof(password),6,STRING},
  		{"-K", (char*)&kill_ruijieclient ,"-k,-K\t\tKill all ruijieclient daemon",sizeof(kill_ruijieclient),2, BOOL_both},
  		{"-k", (char*)&kill_ruijieclient ,0,sizeof(kill_ruijieclient),2, BOOL_both},
  		{0}
  };

  // the initial serial number, a magic number!
  sender.m_serialNo.ulValue = 0x1000002a;


  // Parse command line parameters
  ParseParameters(&argc,&argv,param);

  // if '-g' is passed as argument then generate a sample configuration
  if(genfile)
  {
      GenSetting();
      exit(EXIT_SUCCESS);
  }
 //if '-g' is passed as argument then kill all other ruijieclients which are running
  if (kill_ruijieclient)
  {
	 if(kill_all("ruijieclient"))
		 err_quit("Can not kill ruijieclient, permission denied or no such process");
	 exit(EXIT_SUCCESS);
  }

  if(!nocfg)
  {
	  GetConfig();
  }
  else
  {
	  // get form cmd line, hehe
	  m_nic = nic;
	  sender.m_name = name;
	  sender.m_password = password;
  }
  //NOTE:check if we had get all the config
  CheckConfig();

  // kill all other ruijieclients which are running
  kill_all("ruijieclient");
  kill_all("xgrsu 2> /dev/null");

  strcat(cmd, m_nic);

  if (sender.m_dhcpmode > 0)
    {
      // kill all other dhclients which are running
      kill_all("dhclient");
    }

  if ((sender.m_pcap = pcap_open_live(m_nic, 65536, 0, 500, p_errbuf)) == NULL)
    {
      err_msg("pcap_open_live: %s\n", p_errbuf);

      return 1;
    }
  sender.m_pcap_no = pcap_fileno(sender.m_pcap); // we can poll() it in the following code.

    {
      struct ifreq rif = { { { 0 } } };

      // retrieve MAC address of corresponding net adapter's
      strcpy(rif.ifr_name, m_nic);
      int tmp = socket(AF_INET, SOCK_DGRAM, 0);

      if (m_fakeAddress == NULL)
        {
          ioctl(tmp, SIOCGIFADDR, &rif);
          memcpy(&(sender.m_ip), rif.ifr_addr.sa_data + 2, 4);
        }
      // else m_ip has been initialized in checkandSetConfig()

      ioctl(tmp, SIOCGIFNETMASK, &rif);

      memcpy(&(sender.m_mask), rif.ifr_addr.sa_data + 2, 4);

      ioctl(tmp, SIOCGIFHWADDR, &rif);
      memcpy(sender.m_ETHHDR + ETHER_ADDR_LEN, rif.ifr_hwaddr.sa_data,
          ETHER_ADDR_LEN);
      close(tmp);
    }

  // set the filter. Here I'm sure filter_buf is big enough.
  snprintf(filter_buf, sizeof(filter_buf), FILTER_STR, sender.m_ETHHDR[6],
      sender.m_ETHHDR[7], sender.m_ETHHDR[8], sender.m_ETHHDR[9],
      sender.m_ETHHDR[10], sender.m_ETHHDR[11]);

  if (pcap_compile(sender.m_pcap, &filter_code, filter_buf, 0, sender.m_mask)
      == -1)
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
  signal(SIGTERM, logoff);
  signal(SIGSTOP, logoff);
  signal(SIGTSTP, logoff);

  // search for the server
  beginAuthentication:

  FillVersion(m_fakeVersion); // fill 2 bytes with fake version

  /* comment out for futher usage
   if (m_fakeMAC != NULL)
   {
   //fill m_localMAC with a fake MAC address
   FillFakeMAC(m_localMAC, m_fakeMAC);
   }
   */

  while (1)
    {
      sender.m_state = 0;
LABLE_FINDSERVER:
      if (SendFindServerPacket(&sender))
        {
          continue;
        }
      else
        {
          fputs("@@ Server found, requesting user name...\n", stdout);
        }
LABLE_SENDNAME:
      if (SendNamePacket(&sender))
        {
          continue;
        }
      else
        {
          fputs("@@ User name valid, requesting password...\n", stdout);
        }
LABLE_SENDPASSWD:
      switch (SendPasswordPacket(&sender))
        {
      case -1:
        continue;
      case 1:
        /* authenticate fail
         * possible reasons:
         * 1. user name and password mismatch
         * 2. not in the right time-period of net accessing
         * 3. account has been logged at other computers
         */
        GetServerMsg(&sender, u_msgBuf, MAX_U_MSG_LEN);
        fprintf(stdout, "@@ Authentication failed: %s\n", u_msgBuf);
        SendEndCertPacket(&sender);
        continue;
      case 0:// Authenticate successfully
        sender.m_state = 1;
        break;
        }

      if (sender.m_dhcpmode == 2 && noip_afterauth)
        {
          if (system(cmd) == -1)
            {
              err_quit(
                  "Fail in retrieving network configuration from DHCP server");
            }
          noip_afterauth = 0;
        }
      GetServerMsg(&sender, u_msgBuf, MAX_U_MSG_LEN);
      fprintf(stdout, "@@ Password valid, SUCCESS:\n## Server Message: %s\n",
          u_msgBuf);

      if (m_echoInterval <= 0)
        {
          pcap_close(sender.m_pcap);
          return 0; //user has echo disabled
        }
      // continue echoing
      if(!setdaemon)
    	  fputs("Keeping sending echo...\nPress Ctrl+C to logoff \n", stdout);
      else
    	  {
			  fputs("Daemonize and Keeping sending echo...\n", stdout);
			  daemon(0,0);
    	  }
      // start ping monitoring
      if (m_intelligentReconnect == 1)
        {
          while (SendEchoPacket(&sender) == 0)
            {
              //				printf("heart beat\n");
              if (IfOnline(&sender))
                break;
              sleep(m_echoInterval);
            }
          // continue this big loop when offline
          continue;

        }
      if (m_intelligentReconnect > 10)
        {
          time_t time_recon = time(NULL);
          while (1)
            {
              long time_count = time(NULL) - time_recon;
              if (time_count >= m_intelligentReconnect)
                {
                  fputs("Time to reconect!\n", stdout);
                  goto beginAuthentication;
                }
              sleep(m_echoInterval);
            }
        }
      pcap_close(sender.m_pcap);
      return 1; // this should never happen.

      break;
    }// end while
}
static void
CheckConfig()
{
    if ((sender.m_name == NULL) || (sender.m_name[0] == 0))
    err_quit("invalid name found in ruijie.conf!\n");
    if ((sender.m_password == NULL) || (sender.m_password[0] == 0))
    err_quit("invalid password found in ruijie.conf!\n");
    if ((sender.m_authenticationMode < 0) || (sender.m_authenticationMode> 1))
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


#ifdef LIBXML_TREE_ENABLED

static void
get_element(xmlNode * a_node)
  {
    xmlNode *cur_node = NULL;
    char *node_content, *node_name;
    int i;

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
            	if(name[0]==0) // not got from cmd line
            	{
					strncpy(name, node_content, sizeof(name) - 1);
					name[sizeof(name) - 1] = 0;
				}
				sender.m_name = name;
              }
            else if (strcmp(node_name, "Password") == 0)
              {
				if (password[0]==0)// not got from cmd line
				{
					strncpy(password, node_content, sizeof(password) - 1);
					password[sizeof(password) - 1] = 0;
				}
				sender.m_password = password;
              }
            else if (strcmp(node_name, "AuthenticationMode") == 0)
              {
                sender.m_authenticationMode = atoi(node_content);
              }
            else if (strcmp(node_name, "NIC") == 0)
              {
                if(nic[0]==0)
                {
					m_nic = nic;
					for (i = 0; i < strlen(node_content); i++)
					node_content[i] = tolower(node_content[i]);
					strncpy(nic, node_content, sizeof(nic) - 1);
					nic[sizeof(nic) - 1] = 0;
				}
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
GetConfig()
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
    doc = xmlReadFile(config_file, NULL, 0);

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

    /*
     * Not all machine name the first nic eth0
     * So we just have to retrieve the first nic's name
     */
    pcap_if_t *if_t,*cur_nic;
    char	errbuf[256];
    pcap_findalldevs(&if_t,errbuf);
    //Can not open ?
    if(if_t)
	{
		cur_nic = if_t;
		while(cur_nic && cur_nic->flags == PCAP_IF_LOOPBACK )cur_nic = cur_nic->next;
		/*The first non loopback devices */
		if(cur_nic)
			xmlNewChild(setting_node, NULL, BAD_CAST "NIC", BAD_CAST cur_nic->name );
		else //OMG, all you have got is a loopbake devive
			xmlNewChild(setting_node, NULL, BAD_CAST "NIC", BAD_CAST "eth0");
		pcap_freealldevs(if_t);
	}
	else //So we have to assume that you are using Linux!
		xmlNewChild(setting_node, NULL, BAD_CAST "NIC", BAD_CAST "eth0");

    xmlNewChild(setting_node, NULL, BAD_CAST "EchoInterval", BAD_CAST "15");
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
    rc = xmlSaveFormatFileEnc(config_file, doc, "UTF-8", 1);

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
  if (sender.m_state)
    {
      SendEndCertPacket(&sender);
    }
  _exit(0);
}

static int
kill_all(char * process)
{
  char cmd[256] = "";
  int cmd_return = 0;

  sprintf(cmd, "killall --signal 2 %s", process);
  cmd_return = system(cmd);
  if (cmd_return < 0)
    {
      err_sys("Killall Failure !");
    }
  return cmd_return;
}

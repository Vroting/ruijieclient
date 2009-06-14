/*********************************************************************************
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun  Microcai                                *
 *********************************************************************************
 *
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

#include "ruijieclient.h"
#include "sendpacket.h"
#include "myerr.h"
#include "blog.h"
#include "prase.h"

// fake MAC, e.g. "00:11:D8:44:D5:0D"
//static char *m_fakeMAC = NULL;

// flag of afterward DHCP status
int noip_afterauth = 1;

char config_file[256] = "/etc/ruijie.conf";

/* These info should be worked out by initialisation portion. */

/* Authenticate Status
 * 0: fail to find server
 * 1: fail to pass Authentication of user name
 * 2: fail to pass Authentication of MD5 sum
 * 3: success
 */

/* kill other processes */
static int
kill_all(char* process);
/*check root*/
static void
check_as_root();

/*Get config*/
void
GetConfig(ruijie_packet * l);
/*generate default settings */
void
GenSetting();

// this is a top crucial change that eliminated all global variables
static ruijie_packet sender =
  { 0 };

/* cleanup on exit when detected Ctrl+C */
static void
logoff(int signo)
{
  if (sender.m_state)
    {
      SendEndCertPacket(&sender);
    }
  _exit(0);
}

int
main(int argc, char* argv[])
{
  /* message buffer define*/
  // utf-8 msg buf. note that each utf-8 character takes 4 bytes
  char u_msgBuf[MAX_U_MSG_LEN];

  // system command
  char cmd[32] = "dhclient -4"; //ipv4 only

  long setdaemon = 0;
  long nodaemon = 0;
  long genfile = 0;
  long kill_ruijieclient = 0;
  long flag_nokill = 0;
  int  try_time = 5 ;
  long showversion = 0;
  char pinghost[32] = "";

  //gonhan 大哥，不要动这个结构体的code style,eclipse 的自动格式化总是把这个搞的更难看
  struct parameter_tags param[] =
  {
    {"--version", (char*)&showversion ,"--version\tShow current version",sizeof(showversion),9, BOOL_both},
    {"-K", (char*)&kill_ruijieclient ,"-k,-K\t\tKill all ruijieclient daemon",sizeof(kill_ruijieclient),2, BOOL_both},
    {"-k", (char*)&kill_ruijieclient ,0,sizeof(kill_ruijieclient),2, BOOL_both},
    {"-M", (char*)&flag_nokill ,0,sizeof(flag_nokill),2, BOOL_both},
    {"--try", (char*)&try_time ,"--try=?\t\tTry number of times of reconnection ",sizeof(try_time),5,INTEGER},
    {"-D", (char*)&nodaemon,"-D\t\tDO NOT fork as a deamon",sizeof(nodaemon),2, BOOL_both},
    {"--daemon", (char*)&setdaemon,"--daemon\trun as a daemon(default)",sizeof(setdaemon),8, BOOL_both},
    {"-n", sender.m_nic ,0,sizeof(sender.m_nic),2, STRING},
    {"--nic", sender.m_nic ,"-n,--nic\tnet card",sizeof(sender.m_nic),5, STRING},
    {"-g", (char*)&genfile ,"-g\t\tauto generate a sample configuration",sizeof(genfile),2, BOOL_both},
    {"--noconfig",(char*)&(sender.m_nocofigfile),"--noconfig\tdo not read config from file",sizeof(sender.m_nocofigfile),10,BOOL_both},
    {"-f",config_file,0,sizeof(config_file),2,STRING},
    {"--config",config_file,"-f,--config\tsupply alternative config file",sizeof(config_file),8,STRING},
    {"-u",sender.m_name ,0,sizeof(sender.m_name),2,STRING},
    {"--user",sender.m_name,"-u,--user\tsupply username",sizeof(sender.m_name),6,STRING},
    {"-p",sender.m_password ,0,sizeof(sender.m_password),2,STRING},
    {"--passwd",sender.m_password,"-p,--passwd\tsupply password",sizeof(sender.m_password),6,STRING},
    {"--dhcpmode",(char*)&sender.m_dhcpmode,"--dhcpmode=?\tdhcpmode, default is 0\n\t\t0:disable\n\t\t1:dhcp before auth\n\t\t2:dhcp after auth,3:dhcp-auth and re-auth after dhcp",sizeof(sender.m_dhcpmode),10,INTEGER},
    {"--pinghost",pinghost,"--pinghost\tthe host to ping(default is your default gateway).\n\t\truijieclient use this to detect network state",sizeof(pinghost),10,STRING},
    {0}
  };

  init_ruijie_packet(&sender);
  // Parse command line parameters
  ParseParameters(&argc, &argv, param);
  if (showversion)
    err_quit("%s", PACKAGE_VERSION);
  // if '-g' is passed as argument then generate a sample configuration
  if (genfile)
    {
      check_as_root();
      GenSetting();
      exit(EXIT_SUCCESS);
    }
  //if '-g' is passed as argument then kill all other ruijieclients which are running
  if (kill_ruijieclient)
    {
      if (kill_all("ruijieclient"))
        err_quit(
            "Can not kill ruijieclient, permission denied or no such process");
      exit(EXIT_SUCCESS);
    }

  if (!sender.m_nocofigfile)
    {
      check_as_root();
      GetConfig(&sender);
    }
  if (pinghost[0])
    sender.m_pinghost = inet_addr(pinghost);

  //NOTE:check if we had get all the config
  CheckConfig(&sender);
#ifndef DEBUG
  // kill all other ruijieclients which are running
  if (!flag_nokill){
	  kill_all("ruijieclient");
  }
  kill_all("xgrsu 2> /dev/null");
#endif
  strcat(cmd, sender.m_nic);

  signal(SIGHUP, logoff);
  signal(SIGINT, logoff);
  signal(SIGQUIT, logoff);
  signal(SIGABRT, logoff);
  signal(SIGTERM, logoff);
  signal(SIGSTOP, logoff);
  signal(SIGTSTP, logoff);

  if (sender.m_nocofigfile)
    check_as_root();

  //print copyright and bug report message
  printf("\n\n%s - a powerful ruijie Supplicant for UNIX, base on mystar.\n"
    "Copyright %s\n\n"
    "Please see/send bug report to \n%s\n"
    "or mail to %s \n\n", PACKAGE,
      "Gong Han, Chen Tingjun, Microcai, sthots, and others",
      "http://code.google.com/p/ruijieclient/issues/list", PACKAGE_BUGREPORT);

  int tryed;
  for (tryed = 0; (tryed < try_time)||(try_time == -1); ++tryed)
    {
      sender.m_state = 0;
#ifdef DEBUG
      GetNicParam(&sender);
#else
      if (GetNicParam(&sender))
        err_quit("Err getting net parameters");
#endif
      FillVersion(&sender); // fill 2 bytes with fake version

      FlushRecvBuf(&sender);
      LABE_FINDDSERVER:
      // search for the server
      if (SendFindServerPacket(&sender))
        {
          continue;
        }
      else
        {
          fputs("@@ Server found, requesting user name...\n", stdout);
        }
      LABLE_SENDNAME: if (SendNamePacket(&sender))
        {
          continue;
        }
      else
        {
          fputs("@@ User name valid, requesting password...\n", stdout);
        }
      //LABLE_SENDPASSWD:
      switch (SendPasswordPacket(&sender))
        {
      case -1:
        //
        goto LABLE_SENDNAME;
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

      /*
       * DHCP mode:
       * 0: Off
       * 1: On, DHCP before authentication
       * 2: On, DHCP after authentication
       * 3: On, DHCP after DHCP authentication and re-authentication       *
       */
      if (sender.m_dhcpmode == 3)
        {
          if (system(cmd))
            {
              err_quit("DHCP error!");
            }
          sender.m_dhcpmode = 0;
          sender.m_ip = 0;
          continue; // re-authentication
        }

      if (sender.m_echoInterval <= 0)
        {
          pcap_close(sender.m_pcap);
          return 0; //user has echo disabled
        }
      // continue echoing
      if (nodaemon)
        fputs("Keeping sending echo...\nPress Ctrl+C to logoff \n", stdout);
      else
        {
          fprintf(stdout,
              "Daemonize and Keeping sending echo...\nUse %s -K to quit",
              PACKAGE_TARNAME);
          if (daemon(0, 0))
            {
              err_quit("Init daemon error!");
            }
        }
      // start ping monitoring
      FlushRecvBuf(&sender);
      if (sender.m_intelligentReconnect == 1)
        {
          while (SendEchoPacket(&sender) == 0)
            {
              //				printf("heart beat\n");
              if (IfOnline(&sender))
                break;
              sleep(sender.m_echoInterval);
            }
          // continue this big loop when offline
          tryed = 0; // or we will not truly re-connect.
          continue;
        }
      if (sender.m_intelligentReconnect > 10)
        {
          time_t time_recon = time(NULL);
          while (1)
            {
              long time_count = time(NULL) - time_recon;
              if (time_count >= sender.m_intelligentReconnect)
                {
                  fputs("Time to reconect!\n", stdout);
                  goto LABE_FINDDSERVER;
                }
              sleep(sender.m_echoInterval);
            }
        }
      pcap_close(sender.m_pcap);
      return EXIT_FAILURE; // this should never happen.
      break;
    }// end while
  if (tryed >= 3)
    fprintf(stderr, "##重试太多，退出\n");
  return (EXIT_FAILURE);
}

static int
kill_all(char * process)
{
  char cmd[256] = "";
  int cmd_return = 0;

  sprintf(cmd, "killall -2 %s", process);
  cmd_return = system(cmd);
  if (cmd_return < 0)
    {
      err_sys("Killall Failure !");
    }
  return cmd_return;
}

static void
check_as_root()
{
#ifndef DEBUG
  if (geteuid() != 0)
    {
      err_sys("Ruijieclient must be run as root.");
    }
#endif
}

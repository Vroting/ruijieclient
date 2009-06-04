#ifndef GLOBAL_H
#define GLOBAL_H

#define FILTER_STR "ether[12:2]=0x888e and ether dst %02x:%02x:%02x:%02x:%02x:%02x"

#define MAX_MSG_LEN 1024
#define MAX_U_MSG_LEN MAX_MSG_LEN*2-lxml2

#define C_VERSION "0.1.1"
#define CONF_NAME "ruijie.conf"
//#define CONF_PATH "/etc/ruijie.conf"
#define CONF_PATH "./ruijie.conf"
#define TMP_FILE "/tmp/ruijieclient_tmp"

#include <sys/types.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

/* a macro defines debug status */
//#define DEBUG 1

typedef union
{
  u_int32_t ulValue;
  u_int8_t btValue[4];
} ULONG_BYTEARRAY;

// user name
extern char *m_name  ;
// password
extern char *m_password  ;
// auth mode: 0:standard 1:Star private
extern int m_authenticationMode ;
// indicator of adapter
extern char *m_nic  ;
// echo interval, 0 means disable echo
extern int m_echoInterval  ;
// Intelligent Reconnect 0:disable, 1: enable.
extern int m_intelligentReconnect  ;
// fake ip, e.g. "123.45.67.89"
extern char *m_fakeAddress  ;
// fake version, e.g. "3.22"
extern char *m_fakeVersion  ;
// fake MAC, e.g. "00:11:D8:44:D5:0D"
extern char *m_fakeMAC  ;
// detective gateway address
extern char m_intelligentHost[16]  ;
// DHCP mode: 0: Off, 1:On, DHCP before authentication, 2: On, DHCP after authentication
extern int m_dhcpmode  ;
// flag of afterward DHCP status
extern int noip_afterauth ;

extern char name[32];
extern char password[32];
extern char nic[32];
extern char fakeAddress[32];
extern char fakeVersion[8];
extern char fakeMAC[32];


/* These info should be worked out by initialisation portion. */

// local MAC
extern unsigned char m_localMAC[6];
// server MAC
extern unsigned char m_destMAC[6];
// IP of selected adapter
extern unsigned char m_ip[4];
// sub mask of selected adapter
extern unsigned char m_netmask[4];
// default route of selected adapter
extern unsigned char m_netgate[4];
// DNS of selected adapter
extern unsigned char m_dns1[4];

/* Authenticate Status
 * 0: fail to find server
 * 1: fail to pass Authentication of user name
 * 2: fail to pass Authentication of MD5 sum
 * 3: success
*/
extern volatile sig_atomic_t m_state  ;

// serial number, initialised when received the first valid Authentication-Success-packet
extern ULONG_BYTEARRAY m_serialNo;
// password private key, initialised at the beginning of function main()
extern ULONG_BYTEARRAY m_key;


#endif /*GLOBAL_H*/

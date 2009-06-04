#include "global.h"

// user name
char *m_name = NULL;
// password
char *m_password = NULL;
// auth mode: 0:standard 1:Star private
int m_authenticationMode = -1;
// indicator of adapter
char *m_nic = NULL;
// echo interval, 0 means disable echo
int m_echoInterval = -1;
// Intelligent Reconnect 0:disable, 1: enable.
int m_intelligentReconnect = -1;
// fake ip, e.g. "123.45.67.89"
char *m_fakeAddress = NULL;
// fake version, e.g. "3.22"
char *m_fakeVersion = NULL;
// fake MAC, e.g. "00:11:D8:44:D5:0D"
char *m_fakeMAC = NULL;
// detective gateway address
char m_intelligentHost[16] = "4.2.2.2";
// DHCP mode: 0: Off, 1:On, DHCP before authentication, 2: On, DHCP after authentication
int m_dhcpmode = 0;
// flag of afterward DHCP status
int noip_afterauth=1;

char name[32];
char password[32];
char nic[32];
char fakeAddress[32];
char fakeVersion[8];
char fakeMAC[32];


/* These info should be worked out by initialisation portion. */

// local MAC
unsigned char m_localMAC[6];
// server MAC
unsigned char m_destMAC[6];
// IP of selected adapter
unsigned char m_ip[4];
// sub mask of selected adapter
unsigned char m_netmask[4];
// default route of selected adapter
unsigned char m_netgate[4];
// DNS of selected adapter
unsigned char m_dns1[4];

/* Authenticate Status
 * 0: fail to find server
 * 1: fail to pass Authentication of user name
 * 2: fail to pass Authentication of MD5 sum
 * 3: success
*/
volatile sig_atomic_t m_state = 0;

// serial number, initialised when received the first valid Authentication-Success-packet
ULONG_BYTEARRAY m_serialNo;
// password private key, initialised at the beginning of function main()
ULONG_BYTEARRAY m_key;

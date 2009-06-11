/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun microcai (microcai@sina.com)             *
 \*******************************************************************************/

/*
 * This program is modified from MyStar, the original author is netxray@byhh.
 *
 * Many thanks to netxray@byhh
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

#ifndef SENDPACKET_H
#define SENDPACKET_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#else
#define ETHER_ADDR_LEN  ETH_HLEN

#endif
#include <pcap.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>


#include "global.h"

typedef struct __ruijie_packet
{
  pcap_t *m_pcap;
  int m_pcap_no;

  int m_lastID; // last ID send form server.
  int m_MD5value_len; // MD5 key
  /*
   * DHCP mode:
   * 0: Off
   * 1: On, DHCP before authentication
   * 2: On, DHCP after authentication
   * 3: On, DHCP after DHCP authentication and re-authentication
   *
   */

  int m_dhcpmode;
  // auth mode: 0:standard 1:Star private
  int m_authenticationMode;

  // echo interval, 0 means disable echo
  int m_echoInterval;
  // Intelligent Reconnect 0:disable, 1: enable.
  int m_intelligentReconnect;

  int m_state; //1 if online

  // fake version, e.g. "3.22"
  char *m_fakeVersion;


  char  m_name[32]; // user name
  char  m_password[32]; // password
  char 	m_nic[32]; // net adapter name

  in_addr_t m_ip;
  in_addr_t m_mask;
  in_addr_t m_gate; //Default gateway
  in_addr_t m_dns;
  // serial number, initialised when received the first valid Authentication-Success-packet
  ULONG_BYTEARRAY m_serialNo;
  // password private key, initialised at the beginning of function main()
  ULONG_BYTEARRAY m_key;

  u_char m_MD5value[64]; //private key
  /*
   * MAC 帧头 . This is a header that contains both local MAC address
   * and SERVER MAC address
   */
  u_char m_ETHHDR[ETH_HLEN];

  u_char circleCheck[2]; // two magic vaules!
  u_char* m_ruijieExtra;


  struct pcap_pkthdr *pkt_hdr;
  const u_char *pkt_data;

} ruijie_packet;

/*
 * The functions below return 0 for success while -1 for failure. However, they should never
 * return -1 normally, hence, we usually ignore return values FOR CONVENIENCE. They might be
 * helpful for debug.
 */

/* fill packets with 2 bytes indicates fake version */
int
FillVersion(ruijie_packet*);

/*get nic param*/
int
GetNicParam(ruijie_packet *this);

/* comment out for further usage
 * Fill MAC bytes in packets with a fake one
 int
 FillFakeMAC(unsigned char * des_MAC, char * m_fakeMAC);
 */

/* send server finding packet */
int
SendFindServerPacket(ruijie_packet *l);

/* send authenticate name packet */
int
SendNamePacket(ruijie_packet *);

/* send authenticate password packet */
int
SendPasswordPacket(ruijie_packet *);

/* send periodical keep-alive echo packet */
int
SendEchoPacket(ruijie_packet *);

/* send end certification packet */
int
SendEndCertPacket(ruijie_packet *);
/* To found out if it's still online */
int
IfOnline(ruijie_packet*this);

/*Flush the recv buffer*/
int
FlushRecvBuf(ruijie_packet*this);
/*Get Server message in UTF-8 encode*/
int
GetServerMsg(ruijie_packet*this, char*outbuf, size_t buflen);
/* default version bytes macro */
//#define VER1 0x0F
//#define VER2 0xFF
//#define DHCP_FLAG 0xFF


#endif

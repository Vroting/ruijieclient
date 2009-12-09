/*
 * packetsender.c : wrapper of libpcap , send and receive packages *
 *
 *  Created on: 2009-12-9
 *      Author: microcai <microcai AT sina.com > from ZSTU
 *
 *
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_NET_IF_DL_H
#include <sys/param.h>
#include <net/if_dl.h>
#define _OS_BSD_ BSD
#else

#endif

#include "packetsender.h"

/**************************************
 * Define pcap_* macro , to use or no to use static link
 **************************************/

/**************************************
 * static variable here
 **************************************/
static const    char    FILTER_STR[]="ether[12:2]=0x888e and ether dst %02x:%02x:%02x:%02x:%02x:%02x";
static pcap_t *         pcap_handle;
static char             pcap_errbuf[PCAP_ERRBUF_SIZE];
static in_addr_t        nic_ip, nic_mask, nic_route, nic_dns;
static char             nic_name[PCAP_ERRBUF_SIZE];
static char             nic_hwaddr[6];
/*
 * open libpcap.so.*
 */
#ifdef USE_DYLIBPCAP

int
open_lib()
{

}

#endif

int
pkt_open_link(const char * _nic_name)
{
  struct ifaddrs * pifaddrs, *pifaddr;
#ifndef HAVE_NET_IF_DL_H
  int sock;
  struct ifreq rif;
#endif
  struct bpf_program filter_code;
  char filter_buf[256];

  strncpy(nic_name, _nic_name, PCAP_ERRBUF_SIZE);

  if (getifaddrs(&pifaddrs))
    {
      fprintf(stderr, "cannot get net interfaces!\n");
      return -1;
    }
#ifndef SIOCGIFHWADDR
  if (!getifaddrs(&pifaddrs))
    {
      for (pifaddr = pifaddrs; pifaddr; pifaddr = pifaddr->ifa_next)
        {
          if (pifaddr->ifa_name && pifaddr->ifa_name[0] && !strcmp(
                  (const char*) pifaddr->ifa_name, nic_name))
            {
              nic_ip = ((struct sockaddr_in*) pifaddr->ifa_addr)->sin_addr.s_addr;
              nic_mask = ((struct sockaddr_in*) pifaddr->ifa_netmask)->sin_addr.s_addr;

              const struct sockaddr_dl * sdl = (struct sockaddr_dl*) pifaddr->ifa_addr;
              memcpy(nic_hwaddr, sdl->sdl_data + sdl->sdl_nlen, 6);
              break;
            }
        }
      freeifaddrs(pifaddrs);
    }
  else
    {
      return -1;
    }
#else

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (!ioctl(sock, SIOCGIFHWADDR, &rif))
    {
      memcpy(nic_hwaddr, rif.ifr_hwaddr.sa_data, 6);
    }
  else
    {
      fprintf(stderr, "Err getting %s address\n", nic_name);
      close(sock);
      return -1;
    }

  if (!ioctl(sock, SIOCGIFADDR, &rif))
    memcpy(&nic_ip, rif.ifr_addr.sa_data + 2, 4);

  if (!ioctl(sock, SIOCGIFNETMASK, &rif))
    memcpy(&nic_mask, rif.ifr_addr.sa_data + 2, 4);
  else
    nic_mask = inet_addr("255.255.255.0");
  close(sock);

#endif //SIOCGIFHWADDR
  if (!(pcap_handle = pcap_open_live(nic_name, 65536, 0, 2000, pcap_errbuf)))
    {
      fprintf(stderr, "Cannot open nic %s :%s", nic_name, pcap_errbuf);
      return -1;
    }

  snprintf(filter_buf, sizeof(filter_buf), FILTER_STR, nic_hwaddr[0], nic_hwaddr[0],
      nic_hwaddr[0], nic_hwaddr[0], nic_hwaddr[0], nic_hwaddr[0]);

  if (pcap_compile(pcap_handle, &filter_code, filter_buf, 0, nic_mask) == -1)
    {
      fprintf(stderr,"pcap_compile(): %s", pcap_geterr(pcap_handle));
      pcap_close(pcap_handle);
      return 1;
    }
  if (pcap_setfilter(pcap_handle, &filter_code) == -1)
    {
      fprintf(stderr,"pcap_setfilter(): %s", pcap_geterr(pcap_handle));
      pcap_close(pcap_handle);
      return 1;
    }
  pcap_freecode(&filter_code); // avoid  memory-leak



  return (0);
}

int
pkt_get_param(int what,struct sockaddr * sa_data)
{

  return -1;
}

int pkt_build_ruijieextra()
{

}

int pkt_build_ruijie()
{

}

int pkt_build_eap()
{

}

int pkt_build_pap()
{

}

int pkt_build_ethernet()
{

}

int pkt_write_link()
{

}

int pkt_read_link()
{

}

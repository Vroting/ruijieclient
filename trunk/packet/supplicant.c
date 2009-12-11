/*
 * supplicant.c : the ruijie supplicant auth engine
 *
 *  Created on: 2009-12-11
 *      Author: <microcai AT sina.com > from ZSTU *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include "packetsender.h"

#define EAP_START       1


static u_char           ruijie_dest[6];
static u_char f;


int ruijie_start(int broadcastmethod)
{
  u_char broadcast[2][6]=
    {
        { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 }, // standard broadcast addr
        { 0x01, 0xD0, 0xF8, 0x00, 0x00, 0x03 } // ruijie private broadcast addr
    };
  struct sockaddr       so_addr;

  pkt_build_ruijie(0,0);
  pkt_build_8021x(1,EAP_START,4);
  pkt_get_param(PKT_PG_HWADDR,&so_addr);

  pkt_build_ethernet(broadcast[broadcastmethod],so_addr.sa_data,ETH_PROTO_8021X);
  pkt_write_link();
}


int start_auth(char * name,char*passwd,char* nic_name,int authmode)
{
  pkt_open_link(nic_name);
  return 0;
}



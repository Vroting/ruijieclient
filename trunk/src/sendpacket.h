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

#ifndef SENDPACKET_H
#define SENDPACKET_H

#include <openssl/md5.h>
#include <string.h>
#include <sys/types.h>
#include <libnet.h>

/*
 * The functions below return 0 for success while -1 for failure. However, they should never
 * return -1 normally, hence, we usually ignore return values FOR CONVENIENCE. They might be
 * helpful for debug.
 */

/* compute hash code from src */
unsigned char *
ComputeHash(unsigned char * src, int i);

/* fill packets with 2 bytes indicates fake version */
int
FillVersion(char * m_fakeVersion);

/* comment out for further usage
 * Fill MAC bytes in packets with a fake one
int
FillFakeMAC(unsigned char * des_MAC, char * m_fakeMAC);
*/

/* send server finding packet */
int
SendFindServerPacket(libnet_t *l);

/* send authenticate name packet */
int
SendNamePacket(libnet_t *l, const u_char *pkt_data);

/* send authenticate password packet */
int
SendPasswordPacket(libnet_t *l, const u_char *pkt_data);

/* send periodical keep-alive echo packet */
int
SendEchoPacket(libnet_t *l, const u_char *pkt_data);

/* send end certification packet */
int
SendEndCertPacket(libnet_t *l);

/* default version bytes macro */
#define VER1 0x0F
#define VER2 0xFF
#define DHCP_FLAG 0xFF

#endif

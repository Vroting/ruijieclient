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

/**********************************************************************************************
 The functions below return 0 for success while -1 for failure. However, they should never
 return -1 normally, hence, we usually ignore return values FOR THE SAKE OF TAKING CONVENIENCE.
 For the motive to debug, they might be helpful.
 **********************************************************************************************/

unsigned char *
ComputeHash(unsigned char * src, int i);

int
FillVersion(char * m_fakeVersion);

int
FillFakeMAC(unsigned char * des_MAC, char * m_fakeMAC);

int
SendFindServerPacket(libnet_t *l);

int
SendNamePacket(libnet_t *l, const u_char *pkt_data);

int
SendPasswordPacket(libnet_t *l, const u_char *pkt_data);

int
SendEchoPacket(libnet_t *l, const u_char *pkt_data);

int
SendEndCertPacket(libnet_t *l);

#define ver1 0x0F
#define ver2 0xFF

#endif

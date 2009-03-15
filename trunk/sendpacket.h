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
 *   Gong Han  <gonghan1989@gmail.com> from CSE@FJNU CN
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
  Those 5 functions below return 0 if ok, -1 if fail. However they should never fail normally,
  so we usually ignore the return values JUST FOR CONVENIENCE.
  If detecting the errors,which might happen, is very important to your program, don't ingore it.
**********************************************************************************************/

unsigned char *
ComputeHash(unsigned char * src, int i);

int
FillVersion(char * m_fakeVersion);

int
FillFakeMAC(char * m_fakeMAC, unsigned char * des_MAC);

int
SendFindServerPacket(libnet_t *l);

int
SendNamePacket(libnet_t *l, const u_char *pkt_data);

int
SendPasswordPacket(libnet_t *l,const u_char *pkt_data);

int
SendEchoPacket(libnet_t *l,const u_char *pkt_data);

int
SendEndCertPacket(libnet_t *l);

#define ver1 0x0F
#define ver2 0xFF

#endif

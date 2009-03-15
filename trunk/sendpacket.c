 /************************************************************************\
 * RuijieClient -- A command-line Ruijie authentication program for Linux *
 *                                                                        *
 * Copyright (C) Gong Han, Chen Tingjun                                   *
 \************************************************************************/
 
/*
 * This program is based on MyStar, the original author is netxray@byhh.
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

#include "sendpacket.h"
#include "global.h"
#include "blog.h"

//实达专有响应附加包
static
uint8_t ackShida[] =
{
  0xFF,0xFF,0x37,0x77,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x08,0x15,0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,
  0x2E,0x65,0x78,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,ver1,ver2,0x00,0x00,0x00,
  0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,0x92,0x68,
  0x64,0x66,0x92,0x94,0x62,0x66,0x91,0x93,0x95,0x62,0x93,0x93,0x91,0x94,0x64,0x61,
  0x64,0x64,0x65,0x66,0x68,0x94,0x98,0xA7,0x61,0x67,0x65,0x67,0x9C,0x6B
};

//广播包，用于寻找服务器
static
uint8_t broadPackage[0x3E8] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0x01,
  0x00,0x00,0xFF,0xFF,0x37,0x77,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x15,0x00,0x00,0x13,0x11,0x38,0x30,0x32,
  0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,ver1,ver2,0x00,
  0x00,0x00,0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,
  0x92,0x68,0x64,0x66,0x92,0x94,0x62,0x66,0x91,0x93,0x95,0x62,0x93,0x93,0x91,0x94,
  0x64,0x61,0x64,0x64,0x65,0x66,0x68,0x94,0x98,0xA7,0x61,0x67,0x65,0x67,0x9C,0x6B
};

//退出包。
static
uint8_t ExitPacket[]=
{
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0x02,
  0x00,0x00,0xFF,0xFF,0x37,0x77,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x15,0x00,0x00,0x13,0x11,0x38,0x30,0x32,
  0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,ver1,ver2,0x00,
  0x00,0x01,0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,
  0x64,0x91,0x60,0x60,0x65,0x65,0x69,0x61,0x64,0x64,0x94,0x93,0x91,0x92,0x96,0x65,
  0x95,0x64,0x68,0x91,0x62,0x68,0x62,0x94,0x9A,0xD6,0x94,0x68,0x66,0x69,0x6C,0x65
};

//应答包，包括用户名和MD5
static
uint8_t ackPackage[0x3E8] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0x00,
  0x00,0x0D,0x02,0x01,0x00,0x0D,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,
  0xFF,0x37,0x77,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,0x2E,
  0x65,0x78,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

//echo包，用于每5秒钟激活一次
static
uint8_t echoPackage[] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0xBF,
  0x00,0x1E,0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,
  0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
};

int FillVersion(char * m_fakeVersion)
{
  unsigned int c_ver1, c_ver2;

  if (!m_fakeVersion == NULL && \
      sscanf(m_fakeVersion, "%u.%u", &c_ver1, &c_ver2))
    {
#ifdef DEBUG
      printf("## c_ver1=%u ## c_ver2=%u\n", c_ver1, c_ver2);
#endif
      ackShida[0x3B] = broadPackage[0x4D] = ExitPacket[0x4D] = c_ver1;
      ackShida[0x3C] = broadPackage[0x4E] = ExitPacket[0x4E] = c_ver2;
      return 0;
    }
  else
    {
      return -1;
    }
}

int FillFakeMAC(char * m_fakeMAC, unsigned char * fMAC)
{

#ifdef DEBUG
  int i;
#endif

  if (!m_fakeMAC == NULL &&
      sscanf(m_fakeMAC, "%x:%x:%x:%x:%x:%x", &fMAC[0], &fMAC[1], &fMAC[2], \
      &fMAC[3], &fMAC[4], &fMAC[5]))
    {
#ifdef DEBUG
      for (i = 0; i<6; i++)
        printf("## MAC%d=%u ", i, fMAC[i]);
      putchar('\n');
#endif

      return 0;
    }
  else
    {
      return -1;
    }
}

unsigned char *
ComputeHash(unsigned char * src, int i)
{
  MD5_CTX context;
  static unsigned char digest[16];
  MD5_Init(&context);
  MD5_Update(&context, src, i);
  MD5_Final(digest, &context);
  return digest;
}

int
SendFindServerPacket(libnet_t *l)
{

   uint8_t StandardAddr[] = {0x01,0x80,0xC2,0x00,0x00,0x03};
   uint8_t StarAddr[]     = {0x01,0xD0,0xF8,0x00,0x00,0x03};

   extern uint8_t  m_localMAC[6];
   extern int    m_authenticationMode;

   if (m_authenticationMode==1) memcpy(broadPackage,StarAddr,6);
      else memcpy( broadPackage, StandardAddr, 6 );
   memcpy( broadPackage+6, m_localMAC, 6 );   //填充MAC地址

   FillNetParamater( &broadPackage[0x17] );

   fputs(">> Searching for server...\n",stdout);

   return (libnet_write_link(l,broadPackage, 0x3E8)==0x3E8)?0:-1;
}

int
SendNamePacket(libnet_t *l, const u_char *pkt_data)
{

   extern char *m_name;
   extern uint8_t  m_destMAC[6];
   extern uint8_t  m_localMAC[6];
   int nameLen;

   nameLen=strlen(m_name);
   memcpy(ackPackage,m_destMAC,6);  //将目的MAC地址填入组织回复的包
   memcpy(ackPackage+6,m_localMAC,6);  //将本机MAC地址填入组织回复的包
   ackPackage[0x12]=0x02;      //code,2代表应答
   ackPackage[0x13]=pkt_data[0x13];  //id, HERE as if it's alway 1 from ShiDa ??
   *(short *)(ackPackage+0x10) = htons((short)(5+nameLen));//len
   *(short *)(ackPackage+0x14) = *(short *)(ackPackage+0x10);//len
   memcpy(ackPackage+0x17,m_name,nameLen); //填入用户名

   FillNetParamater( &ackShida[0x05] );
   memcpy(ackPackage+0x17+nameLen,ackShida,0x6e);

   fputs(">> Sending user name...\n",stdout);

   return (libnet_write_link(l,ackPackage, 0x3E8)==0x3E8)?0:-1;
}

int
SendPasswordPacket(libnet_t *l,const u_char *pkt_data)
{

   unsigned char   md5Data[256]; //密码,md5 buffer
   unsigned char  *md5Dig;       //result of md5 sum
   int       md5Len=0;

   extern char *m_name;
   extern char *m_password;
   extern uint8_t  m_destMAC[6];
   extern uint8_t  m_localMAC[6];
   int nameLen,passwordLen;

   nameLen=strlen(m_name); passwordLen=strlen(m_password);

   memcpy(ackPackage,m_destMAC,6);
   memcpy(ackPackage+6,m_localMAC,6); //将本机MAC地址填入组织回复的包

   ackPackage[0x12] = 0x02;          //code,2代表应答
   ackPackage[0x13]=pkt_data[0x13];        //id
   *(ackPackage+0x16) = *(pkt_data+0x16);  //type，即应答方式,HERE should alway be 4

   *(short *)(ackPackage+0x10) = htons((short)( 22+nameLen)); //len
   *(short *)(ackPackage+0x14) = *(short *)( ackPackage+0x10 );

   md5Data[md5Len++] = ackPackage[0x13];//ID
   memcpy(md5Data+md5Len,m_password,passwordLen); md5Len+=passwordLen; //密码
   memcpy(md5Data+md5Len,pkt_data+0x18,pkt_data[0x17]); md5Len+=pkt_data[0x17]; //密匙
   md5Dig = (unsigned char *)ComputeHash( md5Data, md5Len);

   ackPackage[0x17]=16;         //length of md5sum is always 16.
   memcpy(ackPackage+0x18,md5Dig,16);

   memcpy(ackPackage+0x28,m_name,nameLen);

   FillNetParamater( &ackShida[0x05] );
   memcpy(ackPackage+0x28+nameLen,ackShida,0x6e);

   fputs(">> Sending password... \n",stdout);
   return (libnet_write_link(l,ackPackage, 0x3E8)==0x3E8)?0:-1;
}

int
SendEchoPacket(libnet_t *l,const u_char *pkt_data)
{

   ULONG_BYTEARRAY uCrypt1,uCrypt2,uCrypt1_After,uCrypt2_After;
   extern ULONG_BYTEARRAY  m_serialNo;
   extern ULONG_BYTEARRAY  m_key;
   extern uint8_t  m_destMAC[6];
   extern uint8_t  m_localMAC[6];

   m_serialNo.ulValue++;
   //m_serialNo is initialized at the beginning of main() of mystar.c, and
   //m_key is initialized in mystar.c when the 1st Authentication-Success packet is received.

   uCrypt1.ulValue = m_key.ulValue + m_serialNo.ulValue;
   uCrypt2.ulValue = m_serialNo.ulValue;

   memcpy( echoPackage, m_destMAC, 6 );
   memcpy( echoPackage+6, m_localMAC, 6 );

   uCrypt1_After.ulValue = htonl( uCrypt1.ulValue );
   uCrypt2_After.ulValue = htonl( uCrypt2.ulValue );

   echoPackage[0x18] = Alog(uCrypt1_After.btValue[0]);
   echoPackage[0x19] = Alog(uCrypt1_After.btValue[1]);
   echoPackage[0x1a] = Alog(uCrypt1_After.btValue[2]);
   echoPackage[0x1b] = Alog(uCrypt1_After.btValue[3]);
   echoPackage[0x22] = Alog(uCrypt2_After.btValue[0]);
   echoPackage[0x23] = Alog(uCrypt2_After.btValue[1]);
   echoPackage[0x24] = Alog(uCrypt2_After.btValue[2]);
   echoPackage[0x25] = Alog(uCrypt2_After.btValue[3]);

   return (libnet_write_link(l,echoPackage, 0x2d)==0x2d)?0:-1;
}

int
SendEndCertPacket(libnet_t *l)
{
   extern uint8_t  m_destMAC[6];
   extern uint8_t  m_localMAC[6];

   memcpy( ExitPacket, m_destMAC, 6 );
   memcpy( ExitPacket+6, m_localMAC, 6 );
   FillNetParamater( &ExitPacket[0x17] );
   fputs(">> Logouting... \n",stdout);
   return (libnet_write_link(l,ExitPacket,0x80)==0x80)?0:-1;
}

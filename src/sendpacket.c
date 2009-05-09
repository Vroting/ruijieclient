/*******************************************************************************\
 * RuijieClient -- a CLI based Ruijie Client authentication modified from mystar *
 *                                                                               *
 * Copyright (C) Gong Han, Chen Tingjun                                          *
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

#include "sendpacket.h"
#include "global.h"
#include "blog.h"

// broadcast packet for finding server
static
uint8_t broadPackage[0x3E8] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,	// Destination MAC
  0x00,0x00,0x00,0x00,0x00,0x00,	// Source MAC
  0x88,0x8E,				// Ethertype = 0x888E (8021X)
  0x01,					// Version = 1
  0x01,					// Packet Type  0x00
                                        // 0x01,EAPOL-Start
                                        // 0x02 ;0x03 ;0x04
  0x00,0x00,				// Packet Body Length
};

// echo packet incorporating user name and MD5 sum
static
uint8_t ackPackage[0x3E8] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,	// Destination MAC
  0x00,0x00,0x00,0x00,0x00,0x00,	// Source MAC
  0x88,0x8E,				// Ethertype = 0x888E (8021X)
  0x01,					// Version = 1
  0x00,					// Packet Type 0x00 ;0x01,EAPOL-Start ;0x02 ;0x03 ;0x04
  0x00,0x00,				// Packet Body Length
  0x02,                                 // Response
  0x00,                                 // id
  0x00,0x00,                            // length
  0x00                                  // type  1 identify  4 MD5-Challenge
};

// end certification packet
static
uint8_t ExitPacket[0x3E8] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,	// Destination MAC
  0x00,0x00,0x00,0x00,0x00,0x00,	// Source MAC
  0x88,0x8E,				// Ethertype = 0x888E (8021X)
  0x01,					// Version = 1
  0x02,					// Packet Type  0x00
                                        // 0x01,EAPOL-Start
                                        // 0x02 ;0x03 ;0x04
  0x00,0x00,				// Packet Body Length
};


// keep-alive echo packet
static
uint8_t echoPackage[] =
{
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0xBF,
  0x00,0x1E,0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,
  0x7F,0x9F,0xF7,0xFF,0x00,0x00,0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
};

//Ruijie OEM Extra （V2.56）  by soar
static uint8_t RuijieExtra[144] = {
// OEM Extra
// 0 --> 22
  0xff,0xff,0x37,0x77, // Encode( 0x00,0x00,0x13,0x11 )
                       // 求反并头尾颠倒.add by lsyer
  0xff,                // Encode( 0x01/00  EnableDHCP flag )
                       // 0xff:Static IP  0x3f:DHCP
  0x00,0x00,0x00,0x00, // Encode( IP )
  0x00,0x00,0x00,0x00, // Encode( SubNetMask )
  0x00,0x00,0x00,0x00, // Encode( NetGate )
  0x00,0x00,0x00,0x00, // Encode( DNS )
  0x00,0x00,           // Checksum( )
// 23 --> 58
// ASCII 8021x.exe
  0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,
// 59 --> 77
  0x00,0x00,0x00,0x00, // 8021x.exe File Version (2.56.00)
                       // base16 code.add by lsyer
  0x00,                // unknow flag
  // Const strings
  0x00,0x00,0x13,0x11,0x00,0x28,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,
  // 78 --> 118
  // 32bits spc. Random strings
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
  // 32bits spc. Random strings
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
  // Const strings
  0x00,0x00,0x13,0x11,0x18,0x06,0x00,0x00,0x00,
  // 119
  0x00,               // DHCP and first time flag
  // V2.56 (and upper?) added
  // 120 -->
  0x1A,0x0E,0x00,0x00,0x13,0x11,0x2D,0x08,  // Const strings
  // 128 --> 141
  0x00,0x00,0x00,0x00,0x00,0x00,            // True NIC MAC
  0x1A,0x08,0x00,0x00,0x13,0x11,0x2F,0x02   // Const strings
};

int
EnableDHCP()
{
    RuijieExtra[0x04] = 0x7f;
}

int
FillVersion(char * m_fakeVersion)
{
  unsigned int c_ver1, c_ver2;

  if (m_fakeVersion && sscanf(m_fakeVersion, "%u.%u", &c_ver1, &c_ver2))
    {
#ifdef DEBUG
      printf("## c_ver1=%u ## c_ver2=%u\n", c_ver1, c_ver2);
#endif
      RuijieExtra[0x3B] = c_ver1;
      RuijieExtra[0x3C] = c_ver2;
      return 0;
    }
  else
    {
      return -1;
    }
}

/* comment out for further usage
int
FillFakeMAC(unsigned char * fMAC, char * m_fakeMAC)
{

#ifdef DEBUG
  int i;
#endif

  if (m_fakeMAC && sscanf(m_fakeMAC, "%x:%x:%x:%x:%x:%x", &fMAC[0],
      &fMAC[1], &fMAC[2], &fMAC[3], &fMAC[4], &fMAC[5]))
    {
#ifdef DEBUG
      printf("## MAC =");
      for (i = 0; i < 6; i++)
        printf(" %2X ", fMAC[i]);
      putchar('\n');
#endif

      return 0;
    }
  else
    {
      return -1;
    }
}
*/

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

  uint8_t StandardAddr[] =
    { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };
  uint8_t StarAddr[] =
    { 0x01, 0xD0, 0xF8, 0x00, 0x00, 0x03 };

  extern uint8_t m_localMAC[6];
  extern int m_authenticationMode;

  if (m_authenticationMode == 1)
    memcpy(broadPackage, StarAddr, 6);
  else
    memcpy(broadPackage, StandardAddr, 6);

  memcpy(broadPackage + 6, m_localMAC, 6); // fill local MAC

  FillNetParamater(&RuijieExtra[0x05]);

  memcpy(broadPackage+18, RuijieExtra, sizeof(RuijieExtra));

  fputs(">> Searching for server...\n", stdout);

  return (libnet_write_link(l, broadPackage, 0x3E8) == 0x3E8) ? 0 : -1;
}

int
SendNamePacket(libnet_t *l, const u_char *pkt_data)
{

  extern char *m_name;
  extern uint8_t m_destMAC[6];
  extern uint8_t m_localMAC[6];
  int nameLen;

  nameLen = strlen(m_name);
  memcpy(ackPackage, m_destMAC, 6); // fill destined MAC
  memcpy(ackPackage + 6, m_localMAC, 6); // fill local MAC
  ackPackage[0x13] = pkt_data[0x13]; //id, HERE as if it's alway 1 from ShiDa ??
  *(short *) (ackPackage + 0x10) = htons((short) (5 + nameLen));// length
  *(short *) (ackPackage + 0x14) = *(short *) (ackPackage + 0x10);// length
  ackPackage[0x16] = 0x01; //Type: Identify
  memcpy(ackPackage + 0x17, m_name, nameLen); // fill name


  memcpy(ackPackage+0x17+nameLen, RuijieExtra, sizeof(RuijieExtra));


  fputs(">> Sending user name...\n", stdout);

  return (libnet_write_link(l, ackPackage, 0x3E8) == 0x3E8) ? 0 : -1;
}

int
SendPasswordPacket(libnet_t *l, const u_char *pkt_data)
{

  unsigned char md5Data[256]; // password,md5 buffer
  unsigned char *md5Dig; // result of md5 sum
  int md5Len = 0;

  extern char *m_name;
  extern char *m_password;
  extern uint8_t m_destMAC[6];
  extern uint8_t m_localMAC[6];
  int nameLen, passwordLen;

  nameLen = strlen(m_name);
  passwordLen = strlen(m_password);

  memcpy(ackPackage, m_destMAC, 6);
  memcpy(ackPackage + 6, m_localMAC, 6); // fill local MAC

  ackPackage[0x13] = pkt_data[0x13]; //id

  ackPackage[0x16] = 0x04; // Type: MD5-Challenge

  *(short *) (ackPackage + 0x10) = htons((short) (22 + nameLen)); // length
  *(short *) (ackPackage + 0x14) = *(short *) (ackPackage + 0x10);

  md5Data[md5Len++] = ackPackage[0x13];//ID
  memcpy(md5Data + md5Len, m_password, passwordLen);
  md5Len += passwordLen; // password
  memcpy(md5Data + md5Len, pkt_data + 0x18, pkt_data[0x17]);
  md5Len += pkt_data[0x17]; // private key
  md5Dig = (unsigned char *) ComputeHash(md5Data, md5Len);

  ackPackage[0x17] = 16; // length of md5 sum is always 16.
  memcpy(ackPackage + 0x18, md5Dig, 16);

  memcpy(ackPackage + 0x28, m_name, nameLen);

  memcpy(ackPackage + 0x28 + nameLen, RuijieExtra, sizeof(RuijieExtra));

  fputs(">> Sending password... \n", stdout);
  return (libnet_write_link(l, ackPackage, 0x3E8) == 0x3E8) ? 0 : -1;
}

int
SendEchoPacket(libnet_t *l, const u_char *pkt_data)
{

  ULONG_BYTEARRAY uCrypt1, uCrypt2, uCrypt1_After, uCrypt2_After;
  extern ULONG_BYTEARRAY m_serialNo;
  extern ULONG_BYTEARRAY m_key;
  extern uint8_t m_destMAC[6];
  extern uint8_t m_localMAC[6];

  m_serialNo.ulValue++;
/* m_serialNo is initialized at the beginning of main() of ruijieclient.c, and
 * m_key is initialized in ruijieclient.c when the 1st Authentication-Success
 * packet is received.
 * */

  uCrypt1.ulValue = m_key.ulValue + m_serialNo.ulValue;
  uCrypt2.ulValue = m_serialNo.ulValue;

  memcpy(echoPackage, m_destMAC, 6);
  memcpy(echoPackage + 6, m_localMAC, 6);

  uCrypt1_After.ulValue = htonl(uCrypt1.ulValue);
  uCrypt2_After.ulValue = htonl(uCrypt2.ulValue);

  echoPackage[0x18] = Alog(uCrypt1_After.btValue[0]);
  echoPackage[0x19] = Alog(uCrypt1_After.btValue[1]);
  echoPackage[0x1a] = Alog(uCrypt1_After.btValue[2]);
  echoPackage[0x1b] = Alog(uCrypt1_After.btValue[3]);
  echoPackage[0x22] = Alog(uCrypt2_After.btValue[0]);
  echoPackage[0x23] = Alog(uCrypt2_After.btValue[1]);
  echoPackage[0x24] = Alog(uCrypt2_After.btValue[2]);
  echoPackage[0x25] = Alog(uCrypt2_After.btValue[3]);

  return (libnet_write_link(l, echoPackage, 0x2d) == 0x2d) ? 0 : -1;
}

int
SendEndCertPacket(libnet_t *l)
{
  extern uint8_t m_destMAC[6];
  extern uint8_t m_localMAC[6];

  memcpy(ExitPacket, m_destMAC, 6);
  memcpy(ExitPacket + 6, m_localMAC, 6);

  memcpy(ExitPacket+18, RuijieExtra, sizeof(RuijieExtra));

  fputs(">> Logouting... \n", stdout);
  return (libnet_write_link(l, ExitPacket, 0x80) == 0x80) ? 0 : -1;
}

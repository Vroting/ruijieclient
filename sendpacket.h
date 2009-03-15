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

/*
 * packetsender.h
 *
 *  Created on: 2009-12-9
 *      Author: cai
 */

#ifndef PACKETSENDER_H_
#define PACKETSENDER_H_

#define ETH_MTU 1500
#define ETH_PROTO_8021X 0x8E88

#define PKT_PG_HWADDR 1
#define PKT_PG_IPADDR 2
#define PKT_PG_IPMASK 3


#define HIBYTE(word) (( ((word) & 0xFF00 ) >>8) & 0xFF)
#define LOBYTE(word) ( word & 0xFF)

#define USE_DYLIBPCAP

#ifdef USE_DYLIBPCAP
int open_lib();
#else
#define open_lib() do{;}while(0)
#endif

#endif /* PACKETSENDER_H_ */

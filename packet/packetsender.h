/*
 * packetsender.h
 *
 *  Created on: 2009-12-9
 *      Author: cai
 */

#ifndef PACKETSENDER_H_
#define PACKETSENDER_H_

#define USE_DYLIBPCAP

#ifdef USE_DYLIBPCAP
int open_lib();
#else
#define open_lib() do{;}while(0)
#endif

#endif /* PACKETSENDER_H_ */

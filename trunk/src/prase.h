/*
 * prase.h
 *
 *  Created on: 2009-6-8
 *      Author: cai
 */

#ifndef PRASE_H_
#define PRASE_H_ 1


#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

enum parameter_types
{
	STUB,		// just a stub.
	BOOL_short,	// just supply or not to set flag
	BOOL_long,	// must use =yes or =no
	BOOL_both,	// please always use these one
	INTEGER,	// parameter is a integer
	STRING,		// parameter is a string.
	FUNCTION	// parameter is a call back function
};

struct parameter_tags{
	const char * const prefix;
	const char * const parameter;
	const char * const discribe;
	const long	 parameter_len;
	const int	 prefix_len;
	const enum	 parameter_types	type;
};
void ParseParameters(int * argc, char ** argv[], struct parameter_tags p_[]);

#ifdef __cplusplus
}
#endif


#endif /* PRASE_H_ */

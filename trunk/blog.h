#ifndef BLOG_H
#define BLOG_H

/* The Blog algorithm is mainly de-assembled out by SnowWings.        */
/* We should thank him very much, because the algorithm is crucial.  */

#include <sys/types.h>
#include <string.h>
#include "myerr.h"

void
InitializeBlog(const unsigned char *m_ip, const unsigned char *m_netmask,
    const unsigned char *m_netgate, const unsigned char *m_dns1);

void
FillNetParamater(unsigned char ForFill[]);

unsigned char
Alog(unsigned char BForAlog);

#endif

/* convert GB into utf-8 */

#ifndef CODECONV_H
#define CODECONV_H

#include <iconv.h>
#include <string.h>
#include <stdio.h>

int
code_convert(char *inbuf, size_t inlen, char *outbuf, size_t outlen);//将GB2312 转化为 UTF-8

#endif

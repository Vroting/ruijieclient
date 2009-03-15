/* convert GB into utf-8 */

#include "codeconv.h"

int
code_convert(char *inbuf, size_t inlen, char *outbuf, size_t outlen)//将GB2312 转化为 UTF-8
{
  iconv_t cd;
  char **pin = &inbuf;
  char **pout = &outbuf;

  cd = iconv_open("UTF-8", "GB18030");
  if (cd == 0)
    return -1;
  memset(outbuf, '\0', outlen);
  if (iconv(cd, pin, &inlen, pout, &outlen) == -1)
    {
      perror("code_convert failed.");
      return -1;
    }
  iconv_close(cd);
  return 0;
}

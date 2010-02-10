#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#securitytest"
#endif

#include "autoconf.h"

int main()
{
#ifdef CONFIG_SECURITYFS
  return 1;
#else
  return 0;
#endif
}

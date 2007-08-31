#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#securitytest"
#endif

#include <linux/autoconf.h>

int main()
{
#ifdef CONFIG_SECURITY
  return 1;
#else
  return 0;
#endif
}

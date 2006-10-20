#include <stdio.h>

#ifdef SEPARATE_UTS_RELEASE
#include "linux/utsrelease.h"
#else
#include "linux/version.h"
#endif

int main()
{
  puts(UTS_RELEASE);

  return 0;
}

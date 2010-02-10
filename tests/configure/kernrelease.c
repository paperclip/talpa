#include <stdio.h>

#ifdef SEPARATE_UTS_RELEASE
  #ifdef GENERATED_UTS_RELEASE
    #include "generated/utsrelease.h"
  #else
    #include "linux/utsrelease.h"
  #endif
#else
#include "linux/version.h"
#endif

int main()
{
  puts(UTS_RELEASE);

  return 0;
}

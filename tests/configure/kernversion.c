#include <stdio.h>

#include "autoconf.h"
#include "linux/version.h"

int main()
{
  printf("%u", LINUX_VERSION_CODE);

  return 0;
}

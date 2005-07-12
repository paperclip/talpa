#include <stdio.h>

#include "linux/version.h"

int main()
{
  puts(UTS_RELEASE);
  
  return 0;
}

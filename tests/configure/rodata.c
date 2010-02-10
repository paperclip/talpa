#include "autoconf.h"

int main()
{
#ifdef CONFIG_DEBUG_RODATA
  return 1;
#else
  return 0;
#endif
}

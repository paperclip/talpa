#include "autoconf.h"

int main()
{
#ifdef CONFIG_SECURITY
  return 0;
#else
  return 1;
#endif
}

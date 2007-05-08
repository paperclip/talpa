#include "linux/autoconf.h"
#include "linux/security.h"

int sb_copy_data(const char *fstype, void *orig, void *copy)
{
  return 0;
}

int main()
{
  struct security_operations ops;

  ops.sb_copy_data = sb_copy_data;

  return 0;
}

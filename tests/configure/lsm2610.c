#include "linux/security.h"

static int inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size)
{
  return 0;
}

int main()
{
  struct security_operations ops;

  ops.inode_getsecurity = inode_getsecurity;

  return 0;
}

#include "linux/security.h"

static inline int inode_init_security (struct inode *inode,
                                                struct inode *dir,
                                                char **name,
                                                void **value,
                                                size_t *len)
{
  return 0;
}

int main()
{
  struct security_operations ops;

  ops.inode_init_security = inode_init_security;

  return 0;
}

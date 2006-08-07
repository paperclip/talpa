#include "linux/security.h"

struct key;

static int key_alloc(struct key *key)
{
    return 0;
}

int main()
{
  struct security_operations ops;

  ops.key_alloc = key_alloc;

  return 0;
}

#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#lsmkeystest"
#endif

#include "linux/security.h"

struct key;

static int lsmkeys_key_alloc(struct key *key)
{
    return 0;
}

int main()
{
  struct security_operations ops;

  ops.key_alloc = lsmkeys_key_alloc;

  return 0;
}

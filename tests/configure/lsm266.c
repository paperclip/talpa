#include "linux/autoconf.h"
#include "linux/security.h"

void bprm_compute_creds(struct linux_binprm* bprm)
{
  return;
}

int main()
{
  struct security_operations ops;

  ops.bprm_compute_creds = bprm_compute_creds;

  return 0;
}

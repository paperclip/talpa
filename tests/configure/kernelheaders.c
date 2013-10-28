#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#kernelheaderstest"
#endif

#include "autoconf.h"

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
#include <linux/posix_types.h>

#ifndef __kernel_long_t
typedef long   __kernel_long_t;
#endif

#ifndef __kernel_ulong_t
typedef unsigned long   __kernel_ulong_t;
#endif
#endif

//~ #include <asm/processor.h>

int main()
{
    return 0;
}

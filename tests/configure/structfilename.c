
/* Build by configure */
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#include <linux/kconfig.h>
#endif

#include <asm-generic/fcntl.h>
#include <linux/fcntl.h>
#include <linux/fs.h>

#ifdef TALPA_HAS_STRUCT_FILENAME
#define TALPA_FILENAME_T struct filename
#else /* ! TALPA_HAS_STRUCT_FILENAME */
#define TALPA_FILENAME_T char
#endif /* TALPA_HAS_STRUCT_FILENAME */

void testfunc();

// Deliberately not called
void testfunc()
{
    char* x = "A";
    TALPA_FILENAME_T* y = getname(x);
}


/* Build by configure */
#include "autoconf.h"
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

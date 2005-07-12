#include <stdio.h>

#include "linux/autoconf.h"

int main()
{
#ifdef CONFIG_X86
    printf("i386");
#else
    printf("unsupported");

    return 1;
#endif
    return 0;
}

#include <stdio.h>

#include "linux/autoconf.h"

int main()
{
#if defined CONFIG_X86_64
    printf("x86_64");
#elif defined CONFIG_X86
    printf("i386");
#else
    printf("unsupported");

    return 1;
#endif
    return 0;
}

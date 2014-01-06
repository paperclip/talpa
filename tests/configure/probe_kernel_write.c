#include "autoconf.h"

#include <linux/uaccess.h>

int main()
{
    int val = 0;
    probe_kernel_write((void*)0,(void*)&val,sizeof(void*));
    return 0;
}

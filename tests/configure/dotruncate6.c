#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include "autoconf.h"
#include <linux/types.h>
#include <linux/fs.h>

/* Kernel 3.0+ test */
int main()
{
    struct dentry *dentry = NULL;
    loff_t start = 0;
    struct file *filp = NULL;
    unsigned int time_attrs = 0;

    return do_truncate(dentry, start, time_attrs, filp);
}

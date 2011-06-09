#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include "autoconf.h"
#include <linux/fs.h>

/* do_truncate(struct dentry*, struct vfsmount*, loff_t, unsigned int, struct file*) */
int main()
{
    struct dentry *dentry = NULL;
    struct vfsmount *mnt = NULL;
    loff_t start = 0;
    unsigned int time_attrs = 0;
    struct file *file = NULL;

    return do_truncate(dentry, mnt, start, time_attrs, file);
}

#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include <linux/autoconf.h>
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct vfsmount *mnt = NULL;
    loff_t start = 0;
    unsigned int time_attrs = 0;
    struct file *file = NULL;

    return do_truncate(dentry, mnt, start, time_attrs, file);
}

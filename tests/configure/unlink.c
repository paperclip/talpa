#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#unlinktest"
#endif

#include "autoconf.h"
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;

    return vfs_unlink(inode, dentry);
}

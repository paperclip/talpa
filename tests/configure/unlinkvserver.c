#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#unlinktest"
#endif

#include <linux/autoconf.h>
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct inode *inode = NULL;
    struct nameidata *nd = NULL;

    return vfs_unlink(inode, dentry, nd);
}
